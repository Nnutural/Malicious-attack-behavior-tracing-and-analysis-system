"""日志分析视图"""
import json
import logging
from pathlib import Path

from flask import Blueprint, abort, current_app, render_template, request

from utils.winlog import (
    extract_host_logs_from_winlogbeat_ndjson,
    extract_host_logs_from_windows_eventlog,
)

bp = Blueprint('logs', __name__)

logger = logging.getLogger(__name__)

PAGE_SIZE = 20
MAX_EVENTS_PER_LOAD = 200
WINLOGBEAT_NDJSON_SOURCE = Path("winlogbeat_output")


def _find_latest_log_file(directory: Path) -> Path | None:
    patterns = ["*.ndjson", "*.json", "winlogbeat*", "*.log"]
    candidates = []
    for pattern in patterns:
        candidates.extend(directory.glob(pattern))
    files = [path for path in candidates if path.is_file()]
    if not files:
        return None
    files.sort(key=lambda path: path.stat().st_mtime, reverse=True)
    return files[0]


def _resolve_ndjson_path() -> Path | None:
    search_paths = [
        WINLOGBEAT_NDJSON_SOURCE,
        Path("data/winlogbeat.ndjson"),
        Path("winlogbeat.ndjson"),
    ]
    for candidate in search_paths:
        if candidate.is_file():
            return candidate
        if candidate.is_dir():
            latest = _find_latest_log_file(candidate)
            if latest:
                return latest
    return None


def _get_logger() -> logging.Logger:
    try:
        return current_app.logger
    except RuntimeError:
        return logger


def _map_event_to_log(event: dict, log_id: int) -> dict:
    event_type = event.get("event_type", "")
    if event_type in ("user_logon_failed",):
        level = "ERROR"
    elif event_type in ("log_clear", "service_install", "group_membership_add", "account_created"):
        level = "WARNING"
    else:
        level = "INFO"

    return {
        "id": log_id,
        "timestamp": event.get("timestamp", ""),
        "hostname": event.get("host_ip", ""),
        "level": level,
        "event_id": event.get("raw_id", ""),
        "message": event.get("description", ""),
        "raw_log": json.dumps(event, ensure_ascii=False, indent=2),
    }


def _load_logs() -> list[dict]:
    log = _get_logger()
    log.warning("Winlog 调试：优先使用系统内采集。")
    try:
        events = extract_host_logs_from_windows_eventlog(
            max_events=MAX_EVENTS_PER_LOAD,
            strict=False,
        )
        if events:
            log.warning("Winlog 调试：系统内采集到 %d 条事件。", len(events))
            return [_map_event_to_log(event, idx + 1) for idx, event in enumerate(events)]
        log.warning("Winlog 调试：系统内采集结果为空，尝试 NDJSON 输入。")
    except PermissionError as exc:
        log.warning("Winlog 调试：系统内采集权限不足：%s", exc)
        try:
            events = extract_host_logs_from_windows_eventlog(
                channels=["System"],
                max_events=MAX_EVENTS_PER_LOAD,
                strict=False,
            )
            if events:
                log.warning("Winlog 调试：System 通道采集到 %d 条事件。", len(events))
                return [_map_event_to_log(event, idx + 1) for idx, event in enumerate(events)]
            log.warning("Winlog 调试：System 通道采集结果为空，尝试 NDJSON 输入。")
        except Exception as sub_exc:
            log.warning("Winlog 调试：System 通道采集失败：%s", sub_exc)
    except NotImplementedError as exc:
        log.warning("Winlog 调试：系统内采集不可用：%s", exc)
    except Exception as exc:
        log.exception("Winlog 调试：系统内采集失败：%s", exc)

    search_paths = [
        WINLOGBEAT_NDJSON_SOURCE,
        Path("data/winlogbeat.ndjson"),
        Path("winlogbeat.ndjson"),
    ]
    log.warning("Winlog 调试：搜索路径：%s", ", ".join(str(p) for p in search_paths))
    ndjson_path = _resolve_ndjson_path()
    if not ndjson_path:
        log.warning("Winlog 调试：未找到 Winlogbeat NDJSON 文件。")
        return []
    log.warning("Winlog 调试：使用 NDJSON 文件：%s", ndjson_path)
    try:
        events = extract_host_logs_from_winlogbeat_ndjson(ndjson_path, strict=False)
    except ValueError as exc:
        log.exception("Winlog 调试：解析 NDJSON 失败：%s", exc)
        return []
    log.warning("Winlog 调试：从 NDJSON 解析到 %d 条事件。", len(events))
    return [_map_event_to_log(event, idx + 1) for idx, event in enumerate(events)]


@bp.route('/')
def list_logs():
    page = request.args.get('page', 1, type=int)
    page = max(page, 1)
    logs = _load_logs()
    start = (page - 1) * PAGE_SIZE
    end = start + PAGE_SIZE
    return render_template('logs.html', logs=logs[start:end], page=page)

@bp.route('/<int:log_id>')
def detail(log_id):
    logs = _load_logs()
    if log_id < 1 or log_id > len(logs):
        abort(404)
    return render_template('log_detail.html', log=logs[log_id - 1])
