"""日志分析视图（SQL Server 版 HostLogs）"""

from __future__ import annotations

import json
import logging

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for

from utils.winlog.service.hostlogs_ingest import ingest_windows_eventlog_to_sqlserver
from utils.winlog.storage.hostlogs_sqlserver import (
    count_hostlogs,
    get_hostlog_by_id,
    list_hostlogs,
    parse_result_json,
)

bp = Blueprint("logs", __name__)
logger = logging.getLogger(__name__)

PAGE_SIZE = 20
MAX_EVENTS_PER_LOAD = 200


def _get_logger() -> logging.Logger:
    try:
        return current_app.logger
    except RuntimeError:
        return logger


def _level_from_event_type(event_type: str) -> str:
    if event_type in ("user_logon_failed",):
        return "ERROR"
    if event_type in ("log_clear", "service_install", "group_membership_add", "account_created"):
        return "WARNING"
    return "INFO"


def _map_row_to_log_item(row) -> dict:
    """
    将 dbo.HostLogs 的一行映射为页面需要的字段：
    logs.html / log_detail.html 目前使用：
    id, timestamp, hostname, level, event_id, message, raw_log
    """
    event = parse_result_json(row.result)
    event_type = str(event.get("event_type") or "")
    return {
        "id": row.id,
        "timestamp": str(event.get("timestamp") or ""),
        "hostname": str(event.get("host_ip") or ""),
        "level": _level_from_event_type(event_type),
        "event_id": str(event.get("raw_id") or ""),
        "message": str(event.get("description") or ""),
        # raw_log：详情页展示“完整日志”；此处优先用 content（更完整），否则用 result
        "raw_log": row.content or row.result or "",
        # 额外给详情页使���（可选）
        "result_json_pretty": json.dumps(event, ensure_ascii=False, indent=2) if event else (row.result or ""),
    }


@bp.route("/", methods=["GET"])
def list_logs():
    page = request.args.get("page", 1, type=int)
    page = max(page, 1)

    offset = (page - 1) * PAGE_SIZE
    rows = list_hostlogs(offset=offset, limit=PAGE_SIZE)
    logs = [_map_row_to_log_item(r) for r in rows]

    total = 0
    try:
        total = count_hostlogs()
    except Exception as exc:
        _get_logger().warning("统计 HostLogs 失败: %s", exc)

    return render_template("logs.html", logs=logs, page=page, total=total)


@bp.route("/collect", methods=["POST"])
def collect():
    """
    点击按钮：扫描本机 Windows Event Log 并入库 dbo.HostLogs。
    """
    log = _get_logger()
    try:
        result = ingest_windows_eventlog_to_sqlserver(max_events=MAX_EVENTS_PER_LOAD, strict=False)
        flash(
            f"采集完成：collected={result['collected']} inserted={result['inserted']} "
            f"skipped={result['skipped']} errors={result['errors']}",
            "info",
        )
    except Exception as exc:
        log.exception("采集入库失败: %s", exc)
        flash(f"采集入库失败：{exc}", "error")

    return redirect(url_for("logs.list_logs"))


@bp.route("/<int:log_id>", methods=["GET"])
def detail(log_id: int):
    row = get_hostlog_by_id(log_id)
    if not row:
        abort(404)
    log_item = _map_row_to_log_item(row)
    return render_template("log_detail.html", log=log_item)