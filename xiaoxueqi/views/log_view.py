"""日志分析视图（SQL Server 版 HostLogs）"""

from __future__ import annotations

import json
import logging
import ipaddress
import platform
import subprocess

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, session, url_for

from config import Config
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
DEFAULT_DB_PORT = 1433
PING_TIMEOUT_MS = 1000


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


def _normalize_db_server(value: str | None) -> str | None:
    if not value:
        return None
    text = value.strip()
    if not text:
        return None
    host = text
    port_text = ""
    if "," in text:
        host, port_text = text.split(",", 1)
    elif ":" in text:
        host, port_text = text.split(":", 1)
    host = host.strip()
    port_text = port_text.strip()
    if not host:
        return None
    if host.lower() != "localhost":
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return None
    if port_text:
        if not port_text.isdigit():
            return None
        port = int(port_text)
        if port < 1 or port > 65535:
            return None
    else:
        port = DEFAULT_DB_PORT
    return f"{host},{port}"


def _get_db_server() -> str:
    return session.get("db_server") or Config.DB_SERVER


def _get_conn_str() -> str:
    return Config.build_sql_conn_str(_get_db_server())


def _ping_server(server: str) -> bool:
    host = server
    if "," in server:
        host = server.split(",", 1)[0].strip()
    elif ":" in server:
        host = server.split(":", 1)[0].strip()
    if not host:
        return False
    if host.lower() in ("localhost", "127.0.0.1"):
        print(f"[ping] skip localhost {host}")
        return True
    if platform.system().lower() == "windows":
        args = ["ping", "-n", "1", "-w", str(PING_TIMEOUT_MS), host]
    else:
        timeout_sec = max(1, int(PING_TIMEOUT_MS / 1000))
        args = ["ping", "-c", "1", "-W", str(timeout_sec), host]
    try:
        result = subprocess.run(args, capture_output=True, text=True, check=False)
    except Exception as exc:
        print(f"[ping] failed: {exc}")
        return False
    print(f"[ping] {' '.join(args)}")
    if result.stdout:
        print(result.stdout.rstrip())
    if result.stderr:
        print(result.stderr.rstrip())
    return result.returncode == 0


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


@bp.route("/db", methods=["POST"])
def set_db_server():
    raw_server = request.form.get("db_server", "")
    if not raw_server.strip():
        session.pop("db_server", None)
        flash("已恢复默认 SQL Server。", "info")
        return redirect(url_for("logs.list_logs"))

    normalized = _normalize_db_server(raw_server)
    if not normalized:
        flash("SQL Server 地址无效，请输入 IPv4 或 localhost。", "error")
        return redirect(url_for("logs.list_logs"))

    reachable = _ping_server(normalized)
    if not reachable:
        flash(f"无法连接到 SQL Server 主机：{normalized}", "error")
        return redirect(url_for("logs.list_logs"))

    session["db_server"] = normalized
    flash(f"SQL Server 已设置为：{normalized}", "info")
    return redirect(url_for("logs.list_logs"))


@bp.route("/", methods=["GET"])
def list_logs():
    page = request.args.get("page", 1, type=int)
    page = max(page, 1)

    db_server = _get_db_server()
    _ping_server(db_server)
    conn_str = _get_conn_str()

    offset = (page - 1) * PAGE_SIZE
    logs = []
    total = 0
    try:
        rows = list_hostlogs(offset=offset, limit=PAGE_SIZE, conn_str=conn_str)
        logs = [_map_row_to_log_item(r) for r in rows]
        total = count_hostlogs(conn_str=conn_str)
    except Exception as exc:
        _get_logger().warning("读取 HostLogs 失败: %s", exc)
        flash(f"读取 HostLogs 失败：{exc}", "error")

    return render_template("logs.html", logs=logs, page=page, total=total, db_server=db_server)


@bp.route("/collect", methods=["POST"])
def collect():
    """
    点击按钮：扫描本机 Windows Event Log 并入库 dbo.HostLogs。
    """
    log = _get_logger()
    db_server = _get_db_server()
    _ping_server(db_server)
    conn_str = _get_conn_str()
    try:
        result = ingest_windows_eventlog_to_sqlserver(
            max_events=MAX_EVENTS_PER_LOAD,
            strict=False,
            conn_str=conn_str,
        )
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
    db_server = _get_db_server()
    _ping_server(db_server)
    conn_str = _get_conn_str()
    row = get_hostlog_by_id(log_id, conn_str=conn_str)
    if not row:
        abort(404)
    log_item = _map_row_to_log_item(row)
    return render_template("log_detail.html", log=log_item)
