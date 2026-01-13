"""主机行为分析视图（客户端 Agent 上报 + 展示为主）

说明：
- 客户端运行 utils/behavior_monitor/client_agent.py 上报到 /behavior/ingest
- 行为分析页面只负责展示/筛选/分页/树与时间线数据
- 为避免误操作，此文件将 /behavior/start /behavior/stop 禁用（不再启动服务器本机监听）
"""

from __future__ import annotations

import logging

from flask import Blueprint, current_app, jsonify, render_template, request

from utils.behavior_monitor.service.hostbehaviors_ingest import ingest_host_behavior_event
from utils.behavior_monitor.storage.hostbehaviors_sqlserver import (
    count_hostbehaviors,
    list_distinct_host_names,
    list_hostbehaviors,
    parse_result_json,
)

bp = Blueprint("behavior", __name__)
logger = logging.getLogger(__name__)


def _get_logger() -> logging.Logger:
    try:
        return current_app.logger
    except Exception:
        return logger


@bp.route("/", methods=["GET"])
def index():
    host_names = []
    try:
        host_names = list_distinct_host_names(limit=200)
    except Exception as exc:
        _get_logger().warning("读取 host_name 下拉列表失败: %s", exc)
    return render_template("behavior.html", host_names=host_names)


@bp.route("/start", methods=["POST"])
def start():
    # 禁用服务器本机监听，防止误操作混入服务器数据
    return jsonify({"ok": False, "message": "已切换为客户端 Agent 上报模式：页面不再启动服务器本机监听。"}), 400


@bp.route("/stop", methods=["POST"])
def stop():
    return jsonify({"ok": False, "message": "已切换为客户端 Agent 上报模式：页面不再启动服务器本机监听。"}), 400


@bp.route("/status", methods=["GET"])
def status():
    # 展示模式无需服务器监听状态
    return jsonify(
        {
            "running": False,
            "started_at": None,
            "uptime_sec": 0,
            "counters": {"inserted": 0, "skipped": 0, "errors": 0},
        }
    )


@bp.route("/ingest", methods=["POST"])
def ingest():
    """
    客户端 Agent 上报入口。
    1) 单条：
       { "event": {...}, "host_name": "client-01", "raw": "..." }
    2) 多条：
       { "events": [{...}, {...}], "host_name": "client-01" }
    返回：inserted/skipped/errors
    """
    data = request.get_json(silent=True) or {}
    host_name = (data.get("host_name") or "").strip() or None

    inserted = 0
    skipped = 0
    errors = 0

    if isinstance(data.get("event"), dict):
        ev = data["event"]
        raw = data.get("raw")
        r = ingest_host_behavior_event(event=ev, raw_content=raw, host_name=host_name)
        inserted += int(r.get("inserted") or 0)
        skipped += int(r.get("skipped") or 0)
        errors += int(r.get("errors") or 0)

    elif isinstance(data.get("events"), list):
        for ev in data["events"]:
            if not isinstance(ev, dict):
                continue
            r = ingest_host_behavior_event(event=ev, raw_content=None, host_name=host_name)
            inserted += int(r.get("inserted") or 0)
            skipped += int(r.get("skipped") or 0)
            errors += int(r.get("errors") or 0)
    else:
        return jsonify({"ok": False, "error": "invalid payload"}), 400

    return jsonify({"ok": True, "inserted": inserted, "skipped": skipped, "errors": errors})


@bp.route("/recent", methods=["GET"])
def recent():
    """
    分页返回最近行为事件：
    ?page=1&page_size=20&host_name=xxx
    """
    host_name = (request.args.get("host_name") or "").strip() or None

    page = request.args.get("page", 1, type=int)
    page = max(page, 1)
    page_size = request.args.get("page_size", 20, type=int)
    page_size = max(5, min(page_size, 100))

    offset = (page - 1) * page_size
    rows = list_hostbehaviors(offset=offset, limit=page_size, host_name=host_name)

    total = 0
    try:
        total = count_hostbehaviors(host_name=host_name)
    except Exception:
        pass

    return jsonify(
        {"ok": True, "total": total, "page": page, "page_size": page_size, "items": [_row_to_item(r) for r in rows]}
    )


def _row_to_item(r) -> dict:
    ev = parse_result_json(r.result)
    ent = ev.get("entities") or {}
    return {
        "id": r.id,
        "timestamp": str(ev.get("timestamp") or ""),
        "host": str(r.host_name or ev.get("host_ip") or ""),
        "event_type": str(ev.get("event_type") or ""),
        "action": str(ev.get("action") or ""),
        "process": str(ent.get("process_name") or ""),
        "pid": ent.get("pid"),
        "ppid": ent.get("parent_pid"),
        "cmd": str(ent.get("command_line") or ""),
        "target_file": ent.get("target_file"),
        "target_ip": ent.get("target_ip"),
        "raw": r.content,
        "event": ev,
    }


@bp.route("/process_tree", methods=["GET"])
def process_tree():
    limit = request.args.get("limit", 500, type=int)
    limit = max(1, min(limit, 2000))
    host_name = (request.args.get("host_name") or "").strip() or None

    rows = list_hostbehaviors(offset=0, limit=limit, host_name=host_name)

    nodes = {}
    edges = []
    for r in rows:
        ev = parse_result_json(r.result)
        if ev.get("event_type") != "process_create":
            continue
        ent = ev.get("entities") or {}
        pid = ent.get("pid")
        ppid = ent.get("parent_pid")
        pname = ent.get("process_name") or "unknown"
        cmd = ent.get("command_line") or ""
        if not isinstance(pid, int) or pid <= 0:
            continue

        if pid not in nodes:
            nodes[pid] = {"id": pid, "label": f"{pname} ({pid})", "cmd": cmd}
        if isinstance(ppid, int) and ppid > 0:
            edges.append({"source": ppid, "target": pid})
            if ppid not in nodes:
                nodes[ppid] = {"id": ppid, "label": f"PID {ppid}", "cmd": ""}

    return jsonify({"ok": True, "nodes": list(nodes.values()), "edges": edges})


@bp.route("/file_timeline", methods=["GET"])
def file_timeline():
    limit = request.args.get("limit", 500, type=int)
    limit = max(1, min(limit, 2000))
    host_name = (request.args.get("host_name") or "").strip() or None

    rows = list_hostbehaviors(offset=0, limit=limit, host_name=host_name)

    wanted = {"file_create", "file_modify", "file_delete", "file_read"}
    events = []
    for r in rows:
        ev = parse_result_json(r.result)
        if ev.get("event_type") not in wanted:
            continue
        ent = ev.get("entities") or {}
        events.append(
            {
                "timestamp": ev.get("timestamp"),
                "event_type": ev.get("event_type"),
                "process_name": ent.get("process_name"),
                "pid": ent.get("pid"),
                "target_file": ent.get("target_file"),
                "file_hash": ent.get("file_hash"),
            }
        )

    events.sort(key=lambda x: x.get("timestamp") or "")
    return jsonify({"ok": True, "events": events})

# 只展示关键新增路由，其余保持你当前文件不变
# 在文件中加入这个路由即可

@bp.route("/host_names", methods=["GET"])
def host_names():
    try:
        names = list_distinct_host_names(limit=500)
        return jsonify({"ok": True, "host_names": names})
    except Exception as exc:
        _get_logger().warning("读取 HostBehaviors host_names 失败: %s", exc)
        return jsonify({"ok": False, "host_names": []})