"""
Winlogbeat NDJSON 解析器：主机日志提取与归一化。

增强点（为 SQLServer 入库/详情展示服务）：
- extract_host_logs_from_windows_eventlog 新增 use_bookmark 参数：
  - True: 增量采集（默认，使用 StateStore 的 last_record_id）
  - False: 每次都抓取最新 max_events（用于演示按钮）
- 当 include_xml=True 时，在归一化结果里附带私有字段：
  - _raw_xml: Windows Event XML 原文（用于 content）
  - _computer_name: 事件所属主机名（用于 host_name）
  这些字段不会影响接口字段；入库时应从 result 中移除。

同时保留兼容能力：
- extract_host_logs_from_winlogbeat_ndjson: 解析 winlogbeat 输出的 ndjson 文件
"""

from __future__ import annotations

import json
import logging
import platform
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from .collector_windows import WindowsEventCollector
from .state_store import StateStore

logger = logging.getLogger(__name__)

EVENT_TYPE_MAP = {
    "4624": "user_logon",
    "4634": "user_logoff",
    "4647": "user_logoff",
    "4625": "user_logon_failed",
    "4688": "process_creation_log",
    "7045": "service_install",
    "4697": "service_install",
    "4720": "account_created",
    "4728": "group_membership_add",
    "4732": "group_membership_add",
    "4756": "group_membership_add",
    "1102": "log_clear",
}

EVENT_TYPE_ALIASES = {"login_success": "user_logon"}
ALLOWED_EVENT_TYPES = set(EVENT_TYPE_MAP.values())

IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
INGEST_DELAY_WARN_MS = 5 * 60 * 1000


def _normalize_key(key: str) -> str:
    return re.sub(r"[\s_]+", "", key).lower()


def _build_event_data_index(event_data: dict[str, Any]) -> dict[str, Any]:
    index: dict[str, Any] = {}
    for key, value in event_data.items():
        norm = _normalize_key(str(key))
        if norm not in index:
            index[norm] = value
    return index


def _get_event_data_value(event_data: dict[str, Any], candidates: list[str]) -> Any | None:
    if not event_data:
        return None
    index: dict[str, Any] | None = None
    for candidate in candidates:
        if candidate in event_data:
            return event_data[candidate]
        if index is None:
            index = _build_event_data_index(event_data)
        norm = _normalize_key(candidate)
        if norm in index:
            return index[norm]
    return None


def _handle_error(strict: bool, message: str, *, filename: str, line_no: int, raw_id: str | None = None) -> None:
    detail = f"{filename}:{line_no}: {message}"
    if raw_id is not None:
        detail += f" (raw_id={raw_id})"
    if strict:
        raise ValueError(detail)
    logger.warning(detail)


def _parse_iso8601(
    value: str,
    *,
    filename: str,
    line_no: int,
    strict: bool,
    raw_id: str | None = None,
) -> datetime | None:
    if not value:
        _handle_error(strict, "缺少时间戳", filename=filename, line_no=line_no, raw_id=raw_id)
        return None

    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    if "." in text:
        head, tail = text.split(".", 1)
        if "+" in tail:
            frac, offset = tail.split("+", 1)
            if len(frac) > 6:
                frac = frac[:6]
            text = f"{head}.{frac}+{offset}"
        elif "-" in tail:
            frac, offset = tail.split("-", 1)
            if len(frac) > 6:
                frac = frac[:6]
            text = f"{head}.{frac}-{offset}"
        else:
            frac = tail
            if len(frac) > 6:
                frac = frac[:6]
            text = f"{head}.{frac}"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError as exc:
        _handle_error(strict, f"时间戳格式无效 '{value}': {exc}", filename=filename, line_no=line_no, raw_id=raw_id)
        return None
    if dt.tzinfo is None:
        logger.warning("%s:%d: 时间戳无时区信息，默认按 UTC 处理: %s", filename, line_no, value)
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _format_zulu(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _extract_event_type_from_record(record: dict[str, Any]) -> str | None:
    event_type = record.get("event_type")
    if not event_type:
        event = record.get("event") or {}
        event_type = event.get("type") or event.get("action")
    if isinstance(event_type, list):
        event_type = event_type[0] if event_type else None
    if not event_type:
        return None
    if event_type in EVENT_TYPE_ALIASES:
        return EVENT_TYPE_ALIASES[event_type]
    if event_type in ALLOWED_EVENT_TYPES:
        return event_type
    return None


def _resolve_event_type(raw_id: str, record_context: dict[str, Any] | None, strict: bool, record_ref: str) -> str | None:
    event_type = EVENT_TYPE_MAP.get(raw_id)
    if event_type:
        return event_type
    if strict:
        logger.debug("%s: 跳过不支持的事件 ID %s", record_ref, raw_id)
        return None
    if record_context:
        event_type = _extract_event_type_from_record(record_context)
        if event_type:
            return event_type
    logger.debug("%s: 跳过不支持的事件 ID %s", record_ref, raw_id)
    return None


def _extract_entities(*, event_type: str, event_data: dict[str, Any], record_context: dict[str, Any] | None, record_ref: str) -> dict[str, Any]:
    entities: dict[str, Any] = {}
    user_value = _get_event_data_value(event_data, ["TargetUserName", "SubjectUserName", "user.name", "user"])
    if user_value:
        entities["user"] = user_value

    src_ip_value = _get_event_data_value(
        event_data,
        ["IpAddress", "SourceNetworkAddress", "Source Network Address", "ClientAddress", "source.ip", "src_ip"],
    )
    if src_ip_value:
        entities["src_ip"] = src_ip_value

    session_id_value = _get_event_data_value(event_data, ["TargetLogonId", "SubjectLogonId", "LogonId"])
    if session_id_value is not None:
        entities["session_id"] = str(session_id_value)
    elif event_type in ("user_logon", "user_logoff", "user_logon_failed"):
        logger.warning("%s: 缺少 session_id，事件类型=%s", record_ref, event_type)

    if event_type == "process_creation_log":
        process_name = _get_event_data_value(event_data, ["NewProcessName", "process.executable", "process.name"])
        pid = _get_event_data_value(event_data, ["NewProcessId", "process.pid"])
        parent_process = _get_event_data_value(event_data, ["ParentProcessName", "process.parent.name"])
        command_line = _get_event_data_value(event_data, ["CommandLine", "process.command_line"])
        if process_name:
            entities["process_name"] = process_name
        if pid:
            entities["pid"] = pid
        if parent_process:
            entities["parent_process"] = parent_process
        if command_line:
            entities["command_line"] = command_line

    if event_type == "service_install":
        service_name = _get_event_data_value(event_data, ["ServiceName", "param1"])
        service_path = _get_event_data_value(event_data, ["ImagePath", "ServiceFileName"])
        if service_name:
            entities["service_name"] = service_name
        if service_path:
            entities["service_path"] = service_path

    if event_type == "account_created":
        new_user = _get_event_data_value(event_data, ["TargetUserName", "SamAccountName"])
        if new_user:
            entities["new_user"] = new_user

    if event_type == "group_membership_add":
        group = _get_event_data_value(event_data, ["TargetUserName", "TargetSid", "GroupName", "Group"])
        member = _get_event_data_value(event_data, ["MemberName", "MemberSid"])
        actor = _get_event_data_value(event_data, ["SubjectUserName"])
        if group:
            entities["group"] = group
        if member:
            entities["member"] = member
        if actor:
            entities["actor"] = actor

    if event_type == "log_clear":
        clear_user = _get_event_data_value(event_data, ["SubjectUserName"])
        if clear_user:
            entities["user"] = clear_user

    return entities


def _build_description(event_type: str, raw_id: str, entities: dict[str, Any]) -> str:
    description_parts = [f"事件类型={event_type}", f"事件ID={raw_id}"]
    if "user" in entities:
        description_parts.append(f"用户={entities['user']}")
    if "src_ip" in entities:
        description_parts.append(f"源IP={entities['src_ip']}")
    if "session_id" in entities:
        description_parts.append(f"会话ID={entities['session_id']}")
    return ", ".join(description_parts)


def _build_host_log_event(
    *,
    raw_id: str,
    event_dt: datetime,
    ingest_dt: datetime | None,
    host_ip: str,
    event_data: dict[str, Any],
    record_context: dict[str, Any] | None,
    strict: bool,
    record_ref: str,
    clock_offset_ms: int,
    enable_time_alignment: bool,
    delays_ms: list[int] | None,
) -> dict | None:
    event_type = _resolve_event_type(raw_id, record_context, strict, record_ref)
    if not event_type:
        return None

    entities = _extract_entities(event_type=event_type, event_data=event_data, record_context=record_context, record_ref=record_ref)

    aligned_dt = event_dt
    if enable_time_alignment and clock_offset_ms:
        aligned_dt = event_dt + timedelta(milliseconds=clock_offset_ms)

    if enable_time_alignment and clock_offset_ms == 0 and ingest_dt is not None:
        delay_ms = int((ingest_dt - event_dt).total_seconds() * 1000)
        entities["_ingest_delay_ms"] = delay_ms
        if delays_ms is not None:
            delays_ms.append(delay_ms)

    return {
        "data_source": "host_log",
        "timestamp": _format_zulu(aligned_dt),
        "host_ip": host_ip,
        "event_type": event_type,
        "raw_id": raw_id,
        "entities": entities,
        "description": _build_description(event_type, raw_id, entities),
    }


def extract_host_logs_from_windows_eventlog(
    *,
    channels: list[str] | None = None,
    event_ids: list[str] | None = None,
    include_xml: bool = False,
    batch_size: int = 512,
    max_events: int = 200,
    timeout_sec: int = 2,
    host_ip: str | None = None,
    clock_offset_ms: int = 0,
    enable_time_alignment: bool = True,
    strict: bool = True,
    state_store: StateStore | None = None,
    prefer_latest: bool = True,
    use_pywin32: bool = True,
    use_wevtutil_fallback: bool = True,
    use_bookmark: bool = True,
) -> list[dict]:
    """
    从 Windows Event Log 系统内采集并归一化主机日志。

    use_bookmark:
      - True（默认）：增量采集（使用 StateStore 的 last_record_id）
      - False：每次抓取最新 max_events（用于按钮重复点击演示）
    """
    if platform.system().lower() != "windows":
        raise NotImplementedError("Windows Event Log 采集仅支持 Windows 平台")

    event_ids = event_ids or sorted(EVENT_TYPE_MAP.keys())
    store = state_store or StateStore()

    if not use_bookmark:
        tmp_path = (StateStore().path.parent / "winevent_state_ephemeral.json")
        store = StateStore(path=tmp_path)

    collector = WindowsEventCollector(
        channels=channels,
        event_ids=event_ids,
        include_xml=include_xml,
        batch_size=batch_size,
        state_store=store,
        prefer_latest=prefer_latest,
        use_pywin32=use_pywin32,
        use_wevtutil_fallback=use_wevtutil_fallback,
    )

    raw_events = collector.collect(max_events=max_events, timeout_sec=timeout_sec)
    results: list[dict] = []

    for index, raw_event in enumerate(raw_events, start=1):
        channel = raw_event.get("channel") or "WindowsEventLog"
        record_id = raw_event.get("record_id")
        record_no = int(record_id) if isinstance(record_id, int) else index
        record_ref = f"{channel}:{record_no}"

        raw_id_value = raw_event.get("event_id")
        if raw_id_value is None:
            _handle_error(strict, "缺少事件 ID", filename=channel, line_no=record_no)
            continue
        raw_id = str(raw_id_value)

        system_time = raw_event.get("system_time_utc")
        event_dt = _parse_iso8601(system_time or "", filename=channel, line_no=record_no, strict=strict, raw_id=raw_id)
        if event_dt is None:
            continue

        host_value = host_ip or raw_event.get("computer_name") or raw_event.get("host_ip")
        if not host_value:
            _handle_error(strict, "缺少主机 IP/主机名", filename=channel, line_no=record_no, raw_id=raw_id)
            continue

        event_data = raw_event.get("event_data")
        if not isinstance(event_data, dict):
            event_data = {}

        ingest_dt = None
        if enable_time_alignment and clock_offset_ms == 0:
            ingest_time = raw_event.get("ingest_time_utc")
            if ingest_time:
                ingest_dt = _parse_iso8601(ingest_time, filename=channel, line_no=record_no, strict=False)

        normalized = _build_host_log_event(
            raw_id=raw_id,
            event_dt=event_dt,
            ingest_dt=ingest_dt,
            host_ip=str(host_value),
            event_data=event_data,
            record_context=None,
            strict=strict,
            record_ref=record_ref,
            clock_offset_ms=clock_offset_ms,
            enable_time_alignment=enable_time_alignment,
            delays_ms=None,
        )
        if not normalized:
            continue

        if include_xml:
            normalized["_raw_xml"] = raw_event.get("xml")
            normalized["_computer_name"] = raw_event.get("computer_name")

        results.append(normalized)

    return results


def extract_host_logs_from_winlogbeat_ndjson(
    ndjson_path: str | Path,
    *,
    strict: bool = True,
    clock_offset_ms: int = 0,
    enable_time_alignment: bool = True,
) -> list[dict]:
    """
    兼容 Winlogbeat output.file 生成的 NDJSON 文件回放。
    这条路径目前页面没用，但 utils.winlog.__init__ 仍导出它，必须保留以免 ImportError。
    """
    path = Path(ndjson_path)
    if not path.exists():
        if strict:
            raise FileNotFoundError(f"未找到 NDJSON 文件: {path}")
        logger.warning("未找到 NDJSON 文件: %s", path)
        return []

    results: list[dict] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        text = line.strip()
        if not text:
            continue
        try:
            record = json.loads(text)
        except json.JSONDecodeError as exc:
            _handle_error(strict, f"NDJSON 解析失败: {exc}", filename=str(path), line_no=line_no)
            continue

        event = record.get("event") or {}
        winlog = record.get("winlog") or {}
        system = winlog.get("system") or {}
        event_data = winlog.get("event_data") or {}

        raw_id = str(event.get("code") or system.get("eventID") or "")
        if not raw_id:
            _handle_error(strict, "缺少 raw_id(event.code)", filename=str(path), line_no=line_no)
            continue

        ts = record.get("@timestamp") or record.get("timestamp") or ""
        event_dt = _parse_iso8601(ts, filename=str(path), line_no=line_no, strict=strict, raw_id=raw_id)
        if event_dt is None:
            continue

        host_obj = record.get("host") or {}
        host_name = host_obj.get("name")
        host_ip = None
        host_ips = host_obj.get("ip")
        if isinstance(host_ips, list) and host_ips:
            host_ip = host_ips[0]
        elif isinstance(host_ips, str):
            host_ip = host_ips

        host_value = host_ip or host_name or "unknown"

        normalized = _build_host_log_event(
            raw_id=raw_id,
            event_dt=event_dt,
            ingest_dt=None,
            host_ip=str(host_value),
            event_data=event_data if isinstance(event_data, dict) else {},
            record_context=record,
            strict=strict,
            record_ref=f"{path.name}:{line_no}",
            clock_offset_ms=clock_offset_ms,
            enable_time_alignment=enable_time_alignment,
            delays_ms=None,
        )
        if normalized:
            results.append(normalized)

    return results