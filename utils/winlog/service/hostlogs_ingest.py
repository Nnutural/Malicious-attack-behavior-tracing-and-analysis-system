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
from typing import Any

from utils.winlog.parser_winlogbeat import extract_host_logs_from_windows_eventlog
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
        include_xml=True,     # 让 event 带 _raw_xml / _computer_name
        use_bookmark=False,   # 关键：按钮每次抓最新 N 条（否则可能一直 0）
        prefer_latest=True,
    )

    inserted = 0
    skipped = 0
    errors = 0

    for ev in events:
        # 取出私有字段
        raw_xml = ev.pop("_raw_xml", None)
        computer_name = ev.pop("_computer_name", None)

        # result：接口 dict JSON（不含私有字段）
        result_json = json.dumps(ev, ensure_ascii=False, sort_keys=True)
        event_hash = _sha256_hex(result_json)

        # content：完整原文，���先 xml，兜底 pretty JSON
        content = raw_xml or json.dumps(ev, ensure_ascii=False, sort_keys=True, indent=2)
        host_name = str(computer_name).strip() if computer_name else None

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
