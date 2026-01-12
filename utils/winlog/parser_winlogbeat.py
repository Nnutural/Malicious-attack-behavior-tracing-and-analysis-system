"""Winlogbeat NDJSON 解析器：主机日志提取与归一化。"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
import xml.etree.ElementTree as ET


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

EVENT_TYPE_ALIASES = {
    "login_success": "user_logon",
}

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


def _parse_iso8601(
    value: str,
    *,
    filename: str,
    line_no: int,
    strict: bool,
    raw_id: str | None = None,
) -> datetime | None:
    if not value:
        _handle_error(
            strict,
            "缺少时间戳",
            filename=filename,
            line_no=line_no,
            raw_id=raw_id,
        )
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
        _handle_error(
            strict,
            f"时间戳格式无效 '{value}': {exc}",
            filename=filename,
            line_no=line_no,
            raw_id=raw_id,
        )
        return None
    if dt.tzinfo is None:
        logger.warning("%s:%d: 时间戳无时区信息，默认按 UTC 处理: %s", filename, line_no, value)
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _format_zulu(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_event_data_from_xml(xml_text: str) -> dict[str, Any]:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return {}
    data: dict[str, Any] = {}
    for elem in root.findall(".//{*}EventData/{*}Data"):
        name = elem.attrib.get("Name")
        if not name:
            continue
        data[name] = (elem.text or "").strip()
    return data


def _get_event_data(record: dict[str, Any]) -> dict[str, Any]:
    winlog = record.get("winlog") or {}
    event_data = winlog.get("event_data") or {}
    if isinstance(event_data, dict) and event_data:
        return event_data
    if event_data and not isinstance(event_data, dict):
        logger.warning("winlog.event_data 类型异常: %s", type(event_data).__name__)
    event = record.get("event") or {}
    xml_text = event.get("original") or winlog.get("xml")
    if xml_text:
        return _parse_event_data_from_xml(xml_text)
    return {}


def _select_host_ip(record: dict[str, Any], override: str | None) -> str | None:
    if override:
        return override
    host = record.get("host") or {}
    host_ip = host.get("ip")
    if isinstance(host_ip, list):
        for item in host_ip:
            if isinstance(item, str) and IPV4_RE.match(item):
                return item
        for item in host_ip:
            if item:
                return str(item)
    elif host_ip:
        return str(host_ip)
    winlog = record.get("winlog") or {}
    computer_name = winlog.get("computer_name")
    if computer_name:
        return str(computer_name)
    agent = record.get("agent") or {}
    hostname = agent.get("hostname")
    if hostname:
        return str(hostname)
    return None


def _get_raw_event_id(record: dict[str, Any]) -> str | None:
    event = record.get("event") or {}
    if "code" in event and event["code"] is not None:
        return str(event["code"])
    winlog = record.get("winlog") or {}
    if "event_id" in winlog and winlog["event_id"] is not None:
        return str(winlog["event_id"])
    return None


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


def _handle_error(
    strict: bool,
    message: str,
    *,
    filename: str,
    line_no: int,
    raw_id: str | None = None,
) -> None:
    detail = f"{filename}:{line_no}: {message}"
    if raw_id is not None:
        detail += f" (raw_id={raw_id})"
    if strict:
        raise ValueError(detail)
    logger.warning(detail)


def extract_host_logs_from_winlogbeat_ndjson(
    ndjson_path: str | Path,
    *,
    host_ip: str | None = None,
    clock_offset_ms: int = 0,
    enable_time_alignment: bool = True,
    strict: bool = True,
) -> list[dict]:
    """从 Winlogbeat NDJSON 中提取并归一化主机日志。

    Args:
        ndjson_path: Winlogbeat NDJSON 文件路径（每行一个 JSON）。
        host_ip: 可选的主机 IP/主机名覆盖值。
        clock_offset_ms: 对事件时间戳应用的固定偏移（毫秒）。
        enable_time_alignment: 是否应用时间对齐与诊断逻辑。
        strict: 为 True 时，字段缺失/格式错误抛出 ValueError。

    Returns:
        归一化后的事件列表，每条包含：
            data_source、timestamp(UTC ISO8601 Z)、host_ip、event_type、
            raw_id、entities、description。

    Raises:
        ValueError: strict=True 时遇到 JSON 解析失败、字段缺失或时间格式错误。
    """
    path = Path(ndjson_path)
    delays_ms: list[int] = []
    results: list[dict] = []

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_no, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                _handle_error(
                    strict,
                    f"JSON 解析失败: {exc}",
                    filename=str(path),
                    line_no=line_no,
                )
                continue

            raw_id = _get_raw_event_id(record)
            if not raw_id:
                _handle_error(
                    strict,
                    "缺少事件 ID（event.code 或 winlog.event_id）",
                    filename=str(path),
                    line_no=line_no,
                )
                continue

            event_type = EVENT_TYPE_MAP.get(raw_id)
            if not event_type:
                if strict:
                    logger.debug(
                        "%s:%d: 跳过不支持的事件 ID %s",
                        path,
                        line_no,
                        raw_id,
                    )
                    continue
                event_type = _extract_event_type_from_record(record)
                if not event_type:
                    logger.debug(
                        "%s:%d: 跳过不支持的事件 ID %s",
                        path,
                        line_no,
                        raw_id,
                    )
                    continue

            ts_value = record.get("@timestamp")
            if not ts_value:
                _handle_error(
                    strict,
                    "缺少 @timestamp",
                    filename=str(path),
                    line_no=line_no,
                    raw_id=raw_id,
                )
                continue
            event_dt = _parse_iso8601(
                ts_value,
                filename=str(path),
                line_no=line_no,
                strict=strict,
                raw_id=raw_id,
            )
            if event_dt is None:
                continue

            aligned_dt = event_dt
            if enable_time_alignment and clock_offset_ms:
                aligned_dt = event_dt + timedelta(milliseconds=clock_offset_ms)

            host_ip_value = _select_host_ip(record, host_ip)
            if not host_ip_value:
                _handle_error(
                    strict,
                    "缺少主机 IP/主机名",
                    filename=str(path),
                    line_no=line_no,
                    raw_id=raw_id,
                )
                continue

            entities: dict[str, Any] = {}
            event_data = _get_event_data(record)

            user_value = _get_event_data_value(
                event_data, ["TargetUserName", "SubjectUserName"]
            )
            if not user_value:
                user_value = (record.get("user") or {}).get("name")
            if user_value:
                entities["user"] = user_value

            src_ip_value = _get_event_data_value(
                event_data, ["IpAddress", "SourceNetworkAddress", "Source Network Address"]
            )
            if not src_ip_value:
                src_ip_value = (record.get("source") or {}).get("ip")
            if src_ip_value:
                entities["src_ip"] = src_ip_value

            session_id_value = _get_event_data_value(
                event_data, ["TargetLogonId", "SubjectLogonId", "LogonId"]
            )
            if session_id_value is not None:
                entities["session_id"] = str(session_id_value)
            elif event_type in ("user_logon", "user_logoff", "user_logon_failed"):
                logger.warning(
                    "%s:%d: 缺少 session_id，事件类型=%s",
                    path,
                    line_no,
                    event_type,
                )

            if event_type == "process_creation_log":
                process_name = _get_event_data_value(event_data, ["NewProcessName"])
                pid = _get_event_data_value(event_data, ["NewProcessId"])
                parent_process = _get_event_data_value(
                    event_data, ["ParentProcessName", "Creator Process Name"]
                )
                command_line = _get_event_data_value(
                    event_data, ["CommandLine", "Process Command Line"]
                )
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
                service_path = _get_event_data_value(
                    event_data, ["ImagePath", "ServiceFileName"]
                )
                if service_name:
                    entities["service_name"] = service_name
                if service_path:
                    entities["service_path"] = service_path

            if event_type == "account_created":
                new_user = _get_event_data_value(
                    event_data, ["TargetUserName", "SamAccountName"]
                )
                if new_user:
                    entities["new_user"] = new_user

            if event_type == "group_membership_add":
                group = _get_event_data_value(
                    event_data, ["TargetUserName", "TargetSid", "GroupName", "Group"]
                )
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

            if enable_time_alignment and clock_offset_ms == 0:
                created_value = (record.get("event") or {}).get("created")
                if created_value:
                    created_dt = _parse_iso8601(
                        created_value,
                        filename=str(path),
                        line_no=line_no,
                        strict=False,
                    )
                    if created_dt is not None:
                        delay_ms = int((created_dt - event_dt).total_seconds() * 1000)
                        entities["_ingest_delay_ms"] = delay_ms
                        delays_ms.append(delay_ms)

            description_parts = [f"事件类型={event_type}"]
            description_parts.append(f"事件ID={raw_id}")
            if "user" in entities:
                description_parts.append(f"用户={entities['user']}")
            if "src_ip" in entities:
                description_parts.append(f"源IP={entities['src_ip']}")
            if "session_id" in entities:
                description_parts.append(f"会话ID={entities['session_id']}")
            description = ", ".join(description_parts)

            results.append(
                {
                    "data_source": "host_log",
                    "timestamp": _format_zulu(aligned_dt),
                    "host_ip": host_ip_value,
                    "event_type": event_type,
                    "raw_id": raw_id,
                    "entities": entities,
                    "description": description,
                }
            )

    if delays_ms:
        negative = sum(1 for value in delays_ms if value < 0)
        large = sum(1 for value in delays_ms if value > INGEST_DELAY_WARN_MS)
        if negative or large:
            logger.warning(
                "采集延迟异常 %s: 负值=%d, 过大=%d, 最小=%d, 最大=%d",
                path,
                negative,
                large,
                min(delays_ms),
                max(delays_ms),
            )

    return results


if __name__ == "__main__":
    import argparse
    import json

    from .session_rebuild import rebuild_logon_sessions

    parser = argparse.ArgumentParser(description="解析 Winlogbeat NDJSON 示例。")
    parser.add_argument("ndjson", nargs="?", default="sample_winlogbeat.ndjson")
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()

    events = extract_host_logs_from_winlogbeat_ndjson(args.ndjson, strict=args.strict)
    print(json.dumps(events[:3], indent=2))
    sessions = rebuild_logon_sessions(events, strict=False)
    print(json.dumps({"session_count": len(sessions)}, indent=2))
