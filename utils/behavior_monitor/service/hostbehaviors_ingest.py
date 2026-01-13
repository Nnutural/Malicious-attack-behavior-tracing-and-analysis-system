from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone

from utils.behavior_monitor.storage.hostbehaviors_sqlserver import insert_hostbehavior

logger = logging.getLogger(__name__)

BEIJING_TZ = timezone(timedelta(hours=8))


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _parse_iso8601(timestamp_value: str | None) -> datetime | None:
    """
    解析 ISO8601（支持 Z 或 +08:00）为 aware datetime。
    """
    if not timestamp_value:
        return None
    text = str(timestamp_value).strip()
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def _to_beijing_naive(dt: datetime | None) -> datetime | None:
    """
    转换为北京时间，并去掉 tzinfo，适配 SQLServer DATETIME2。
    """
    if dt is None:
        return None
    return dt.astimezone(BEIJING_TZ).replace(tzinfo=None)


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
    - event_hash: sha256(result_json_sorted) 去重
    - event_time_utc: 这里按你的要求实际存“北京时间”(UTC+8) 的 DATETIME2
    """
    # result JSON（用于接口/展示）
    result_json = json.dumps(event, ensure_ascii=False, sort_keys=True)
    event_hash = _sha256_hex(result_json)

    # 解析事件时间 -> 存北京时间
    event_dt = _parse_iso8601(str(event.get("timestamp") or ""))
    event_time_beijing = _to_beijing_naive(event_dt)

    try:
        insert_hostbehavior(
            result_json=result_json,
            content=raw_content,
            event_hash=event_hash,
            host_name=host_name,
            event_time_utc=event_time_beijing,
        )
        return {"inserted": 1, "skipped": 0, "errors": 0}
    except Exception as exc:
        msg = str(exc)
        if "2601" in msg or "2627" in msg or "UNIQUE" in msg:
            return {"inserted": 0, "skipped": 1, "errors": 0}
        logger.warning("插入 HostBehaviors 失败: %s", exc)
        return {"inserted": 0, "skipped": 0, "errors": 1}