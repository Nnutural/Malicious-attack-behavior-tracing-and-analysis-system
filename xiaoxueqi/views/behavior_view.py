"""主机行为分析视图（HostBehaviors 入库 + 监听控制 + 可视化数据接口）"""

from __future__ import annotations

import json
import logging
from collections import defaultdict

from flask import Blueprint, current_app, jsonify, render_template, request

from utils.behavior_monitor.service.behavior_manager import BehaviorMonitorManager
from utils.behavior_monitor.storage.hostbehaviors_sqlserver import (
    count_hostbehaviors,
    list_distinct_host_names,
    list_hostbehaviors,
    parse_result_json,
)

bp = Blueprint("behavior", __name__)
logger = logging.getLogger(__name__)

# 简单单例（开发模式 reloader 可能会创建两份进程，这点你后面可优化）
_MANAGER = BehaviorMonitorManager()


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
    return jsonify(_MANAGER.start())


@bp.route("/stop", methods=["POST"])
def stop():
    return jsonify(_MANAGER.stop())


@bp.route("/status", methods=["GET"])
def status():
    return jsonify(_MANAGER.status())


@bp.route("/recent", methods=["GET"])
def recent():
    limit = request.args.get("limit", 50, type=int)
    limit = max(1, min(limit, 500))
    host_name = (request.args.get("host_name") or "").strip() or None

    rows = list_hostbehaviors(offset=0, limit=limit, host_name=host_name)
    items = []
    for r in rows:
        ev = parse_result_json(r.result)
        items.append(
            {
                "id": r.id,
                "timestamp": str(ev.get("timestamp") or ""),
                "host": str(r.host_name or ev.get("host_ip") or ""),
                "event_type": str(ev.get("event_type") or ""),
                "action": str(ev.get("action") or ""),
                "process": str((ev.get("entities") or {}).get("process_name") or ""),
                "pid": (ev.get("entities") or {}).get("pid"),
                "ppid": (ev.get("entities") or {}).get("parent_pid"),
                "cmd": str((ev.get("entities") or {}).get("command_line") or ""),
                "target_file": (ev.get("entities") or {}).get("target_file"),
                "target_ip": (ev.get("entities") or {}).get("target_ip"),
                "raw": r.content,
                "event": ev,
            }
        )

    total = 0
    try:
        total = count_hostbehaviors(host_name=host_name)
    except Exception:
        pass

    return jsonify({"ok": True, "total": total, "items": items})


@bp.route("/process_tree", methods=["GET"])
def process_tree():
    """
    简易进程树：基于 recent events 的 pid/parent_pid 聚合。
    返回 nodes + edges，前端可用 ECharts graph/tree 画。
    """
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
    """
    文件时间线：聚合 file_create/file_modify/file_delete/file_read
    输出按 timestamp 排序的事件列表。
    """
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