"""
HostLogs 入库编排层：
- 只采集 Windows Event Log（不读 NDJSON）
- 调用 utils.winlog.extract_host_logs_from_windows_eventlog 得到 normalized dict
- result: 存 normalized dict 的 JSON 字符串
- content: 存完整日志（这里建议存 normalized dict + 采集参数的“证据串”）
  说明：当前 extract_host_logs_from_windows_eventlog 返回的是归一化后的 dict，
       若你希望 content 存 XML，需要在 winlog 采集链路中额外返回 raw xml。
       这里先用“归一化事件 JSON pretty”作为 content，保证详情页可用。
- event_hash: sha256(result_json_sorted)
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

from utils.winlog import extract_host_logs_from_windows_eventlog
from utils.winlog.storage.hostlogs_sqlserver import insert_hostlog


logger = logging.getLogger(__name__)


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


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
    events = extract_host_logs_from_windows_eventlog(
        max_events=max_events,
        strict=strict,
        # 只扫本机 EventLog，默认 channels=["Security","System"] 已在 winlog 内部设置
        # include_xml=True 目前不会体现在返回结构中（返回的是 normalized dict），
        # 所以这里先不强依赖。后续如果你愿意扩展采集链路再启用。
    )

    inserted = 0
    skipped = 0
    errors = 0

    for ev in events:
        # 1) result：接口文档 dict -> JSON 字符串
        result_json = json.dumps(ev, ensure_ascii=False, sort_keys=True)

        # 2) content：完整日志（先用 pretty JSON，保证可回放）
        # 后续如果你把 Raw XML 串出来，这里直接换成 xml 即可。
        content = json.dumps(ev, ensure_ascii=False, sort_keys=True, indent=2)

        # 3) event_hash：用于去重
        event_hash = _sha256_hex(result_json)

        try:
            insert_hostlog(
                result_json=result_json,
                content=content,
                event_hash=event_hash,
                conn_str=conn_str,
            )
            inserted += 1
        except Exception as exc:
            # 如果你建了 UNIQUE INDEX，重复插入通常会触发 2601/2627 等异常
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
