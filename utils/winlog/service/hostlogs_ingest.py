"""
HostLogs 入库编排层（SQL Server）：
- 只采集 Windows Event Log（不读 NDJSON）
- 使用 extract_host_logs_from_windows_eventlog(include_xml=True) 一次采集：
  - result: 接口 dict（JSON 字符串存入 dbo.HostLogs.result）
  - content: Windows Event XML（存入 dbo.HostLogs.content）
  - host_name: ComputerName（存入 dbo.HostLogs.host_name）
- use_bookmark=False：按钮每次都抓取最新 max_events（演示友好）
- event_hash: sha256(result_json_sorted) 去重
"""

from __future__ import annotations

import hashlib
import json
import logging
import platform
from datetime import datetime, timedelta, timezone
from typing import Any

from utils.winlog.parser_winlogbeat import extract_host_logs_from_windows_eventlog
from utils.winlog.storage.hostlogs_sqlserver import insert_hostlog
from utils.winlog.time_sync import get_last_sync_state

logger = logging.getLogger(__name__)


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _parse_iso8601_utc(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _format_zulu(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _apply_clock_offset(event: dict[str, Any], offset_ms: float) -> None:
    if not offset_ms:
        return
    raw_ts = event.get("timestamp")
    if not raw_ts:
        return
    dt = _parse_iso8601_utc(str(raw_ts))
    if dt is None:
        return
    event["timestamp"] = _format_zulu(dt + timedelta(milliseconds=offset_ms))


def ingest_windows_eventlog_to_sqlserver(
    *,
    max_events: int = 200,
    strict: bool = False,
    conn_str: str | None = None,
) -> dict[str, Any]:
    """
    采集 Windows Event Log 并写入 dbo.HostLogs。

    conn_str 可用于覆盖默认 SQL Server 连接串。

    返回：
    {
      "collected": int,
      "inserted": int,
      "skipped": int,
      "errors": int
    }
    """
    sync_state = get_last_sync_state()
    offset_ms = float(sync_state.get("offset_ms") or 0.0)
    delay_ms = sync_state.get("delay_ms")
    source_ip = sync_state.get("source_ip")
    last_sync_utc = sync_state.get("last_sync_utc")
    clock_status = "synced" if last_sync_utc else "unsynced"
    if clock_status == "unsynced":
        logger.info("未发现有效时钟同步记录，clock_offset_ms=0")

    events = extract_host_logs_from_windows_eventlog(
        max_events=max_events,
        strict=strict,
        include_xml=True,     # 让 event 带 _raw_xml / _computer_name
        use_bookmark=False,   # 关键：按钮每次抓最新 N 条（否则可能一直 0）
        prefer_latest=True,
    )

    inserted = 0
    skipped = 0
    errors = 0

    for ev in events:
        _apply_clock_offset(ev, offset_ms)
        ev["clock_offset_ms"] = offset_ms
        ev["clock_delay_ms"] = delay_ms
        ev["clock_source_ip"] = source_ip
        ev["clock_sync_time_utc"] = last_sync_utc
        ev["clock_status"] = clock_status

        # 取出私有字段
        raw_xml = ev.pop("_raw_xml", None)
        computer_name = ev.pop("_computer_name", None)

        # result：接口 dict JSON（不含私有字段）
        result_json = json.dumps(ev, ensure_ascii=False, sort_keys=True)
        event_hash = _sha256_hex(result_json)

        # content：完整原文，���先 xml，兜底 pretty JSON
        content = raw_xml or json.dumps(ev, ensure_ascii=False, sort_keys=True, indent=2)
        host_name = str(computer_name).strip() if computer_name else None
        if not host_name:
            host_name = platform.node().strip() or None

        try:
            insert_hostlog(result_json=result_json, content=content, event_hash=event_hash, host_name=host_name, conn_str=conn_str)
            inserted += 1
        except Exception as exc:
            msg = str(exc)
            if "2601" in msg or "2627" in msg or "UNIQUE" in msg:
                skipped += 1
                continue
            errors += 1
            logger.warning("插入 HostLogs 失败: %s", exc)

    return {
        "collected": len(events),
        "inserted": inserted,
        "skipped": skipped,
        "errors": errors,
    }
