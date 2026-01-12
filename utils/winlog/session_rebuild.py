"""从归一化主机日志事件重建登录会话。"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any


logger = logging.getLogger(__name__)


def _parse_zulu(value: str, *, index: int, strict: bool) -> datetime | None:
    if not value:
        _handle_error(strict, "缺少时间戳", index=index)
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
        _handle_error(strict, f"时间戳格式无效 '{value}': {exc}", index=index)
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _format_zulu(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _handle_error(strict: bool, message: str, *, index: int) -> None:
    detail = f"事件[{index}]: {message}"
    if strict:
        raise ValueError(detail)
    logger.warning(detail)


def _finalize_session(session: dict[str, Any], end_dt: datetime, status: str) -> dict[str, Any]:
    start_dt = session["_start_dt"]
    if end_dt < start_dt:
        end_dt = start_dt
    session["end_time"] = _format_zulu(end_dt)
    session["status"] = status
    session.pop("_start_dt", None)
    session.pop("_last_dt", None)
    return session


def rebuild_logon_sessions(
    host_log_events: list[dict],
    *,
    session_timeout_sec: int = 8 * 3600,
    strict: bool = True,
) -> list[dict]:
    """从归一化主机日志事件中重建登录会话。

    Args:
        host_log_events: extract_host_logs_from_winlogbeat_ndjson 的输出列表。
        session_timeout_sec: 缺失登出事件时的超时时间（秒）。
        strict: 为 True 时，字段缺失/格式错误抛出 ValueError。

    Returns:
        会话列表，每条包含：
            host_ip、session_id、user（可选）、src_ip（可选）、
            start_time、end_time、events、status（open/closed/timeout）。

    Raises:
        ValueError: strict=True 且必填字段缺失时抛出。
    """
    if not isinstance(host_log_events, list):
        raise ValueError("host_log_events 必须为 list")

    sessions: list[dict] = []
    open_sessions: dict[tuple[str, str], dict[str, Any]] = {}

    for index, event in enumerate(host_log_events):
        if not isinstance(event, dict):
            _handle_error(strict, "事件不是 dict", index=index)
            continue

        event_type = event.get("event_type")
        if event_type not in ("user_logon", "user_logoff", "user_logon_failed"):
            continue

        timestamp = event.get("timestamp")
        event_dt = _parse_zulu(timestamp, index=index, strict=strict)
        if event_dt is None:
            continue

        host_ip = event.get("host_ip")
        if not host_ip:
            _handle_error(strict, "缺少 host_ip", index=index)
            continue

        entities = event.get("entities") or {}
        if not isinstance(entities, dict):
            _handle_error(strict, "entities 必须为 dict", index=index)
            continue

        session_id = entities.get("session_id")
        if not session_id:
            logger.warning("event[%d]: 缺少 session_id，事件类型=%s", index, event_type)
            continue
        session_id = str(session_id)

        key = (str(host_ip), session_id)

        if event_type == "user_logon_failed":
            continue

        if event_type == "user_logon":
            if key in open_sessions:
                existing = open_sessions[key]
                start_dt = existing["_start_dt"]
                last_dt = existing["_last_dt"]
                # Logon ID 只在两次重启之间唯一；当出现重复且时间回退或未关闭时需切分会话。
                if event_dt <= last_dt:
                    end_dt = start_dt + timedelta(seconds=session_timeout_sec)
                else:
                    end_dt = min(start_dt + timedelta(seconds=session_timeout_sec), event_dt)
                sessions.append(_finalize_session(existing, end_dt, "timeout"))
                open_sessions.pop(key, None)

            session: dict[str, Any] = {
                "host_ip": str(host_ip),
                "session_id": session_id,
                "start_time": _format_zulu(event_dt),
                "end_time": None,
                "events": 1,
                "status": "open",
                "_start_dt": event_dt,
                "_last_dt": event_dt,
            }
            if entities.get("user"):
                session["user"] = entities["user"]
            if entities.get("src_ip"):
                session["src_ip"] = entities["src_ip"]
            open_sessions[key] = session
            continue

        if event_type == "user_logoff":
            existing = open_sessions.get(key)
            if not existing:
                logger.warning("event[%d]: 登出事件没有匹配的会话", index)
                continue
            if entities.get("user") and "user" not in existing:
                existing["user"] = entities["user"]
            if entities.get("src_ip") and "src_ip" not in existing:
                existing["src_ip"] = entities["src_ip"]
            existing["events"] += 1
            existing["_last_dt"] = event_dt
            sessions.append(_finalize_session(existing, event_dt, "closed"))
            open_sessions.pop(key, None)

    for session in open_sessions.values():
        timeout_end = session["_start_dt"] + timedelta(seconds=session_timeout_sec)
        sessions.append(_finalize_session(session, timeout_end, "timeout"))

    sessions.sort(key=lambda item: item.get("start_time") or "")
    return sessions


if __name__ == "__main__":
    import argparse
    import json

    from .parser_winlogbeat import extract_host_logs_from_winlogbeat_ndjson

    parser = argparse.ArgumentParser(description="重建登录会话示例。")
    parser.add_argument("ndjson", nargs="?", default="sample_winlogbeat.ndjson")
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()

    events = extract_host_logs_from_winlogbeat_ndjson(args.ndjson, strict=args.strict)
    print(json.dumps(events[:3], indent=2))
    sessions = rebuild_logon_sessions(events, strict=args.strict)
    print(json.dumps(sessions[:3], indent=2))
    print(json.dumps({"session_count": len(sessions)}, indent=2))
