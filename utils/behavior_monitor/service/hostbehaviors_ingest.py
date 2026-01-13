from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone

from utils.behavior_monitor.storage.hostbehaviors_sqlserver import insert_hostbehavior

logger = logging.getLogger(__name__)


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _parse_event_time_utc(timestamp_value: str | None) -> datetime | None:
    """
    解析 result.timestamp（ISO8601，Z结尾）成 datetime2(UTC)。
    失败则返回 None。
    """
    if not timestamp_value:
        return None
    text = timestamp_value.strip()
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).replace(tzinfo=None)  # 存入 SQLServer DATETIME2（无 tz）
    except Exception:
        return None


def ingest_host_behavior_event(
    *,
    event: dict,
    raw_content: str | None,
    host_name: str | None,
) -> dict:
    """
    插入一条 HostBehaviors：
    - result: event dict 的 JSON 字符串（sort_keys=True 用于 hash 稳定）
    - content: 原始字符串（falco raw line 或 sysmon xml）
    - event_hash: sha256(result_json_sorted)
    - event_time_utc: 从 event["timestamp"] 解析
    """
    # result JSON（用于接口/展示）
    result_json = json.dumps(event, ensure_ascii=False, sort_keys=True)
    event_hash = _sha256_hex(result_json)
    event_time_utc = _parse_event_time_utc(str(event.get("timestamp") or ""))

    try:
        insert_hostbehavior(
            result_json=result_json,
            content=raw_content,
            event_hash=event_hash,
            host_name=host_name,
            event_time_utc=event_time_utc,
        )
        return {"inserted": 1, "skipped": 0, "errors": 0}
    except Exception as exc:
        msg = str(exc)
        # SQLServer 唯一索引冲突：2601 / 2627
        if "2601" in msg or "2627" in msg or "UNIQUE" in msg:
            return {"inserted": 0, "skipped": 1, "errors": 0}
        logger.warning("插入 HostBehaviors 失败: %s", exc)
        return {"inserted": 0, "skipped": 0, "errors": 1}