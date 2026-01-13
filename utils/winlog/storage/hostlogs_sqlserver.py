"""
HostLogs (dbo.HostLogs) SQL Server 存储层。

表字段假设：
- id INT IDENTITY PRIMARY KEY
- result NVARCHAR(MAX)   -- 归一化后的 dict（JSON 字符串）
- content NVARCHAR(MAX)  -- 原始完整日志（XML 或 Raw JSON 字符串）
- create_time DATETIME2 DEFAULT(sysdatetime())
- event_hash VARCHAR(64) NULL      -- 用于去���（建议建唯一索引）

建议建立唯一索引（一次性执行）：
CREATE UNIQUE INDEX UX_HostLogs_event_hash
ON dbo.HostLogs(event_hash)
WHERE event_hash IS NOT NULL;
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from utils.db.db import execute, fetch_all, fetch_one


@dataclass
class HostLogRow:
    id: int
    result: str
    content: str | None
    create_time: Any | None = None
    event_hash: str | None = None


def insert_hostlog(*, result_json: str, content: str | None, event_hash: str) -> int:
    """
    插入一条 HostLogs 记录。
    - 若 event_hash 唯一索引存在：重复会抛异常（23000/2601/2627），上层可忽略。
    - create_time 使用数据库默认 sysdatetime()。
    """
    sql = """
    INSERT INTO dbo.HostLogs (result, content, event_hash)
    VALUES (?, ?, ?)
    """
    return execute(sql, [result_json, content, event_hash])


def list_hostlogs(*, offset: int, limit: int) -> list[HostLogRow]:
    """
    分页查询（最新在前）。
    SQL Server: ORDER BY ... OFFSET ... FETCH ...
    """
    sql = """
    SELECT id, result, content, create_time, event_hash
    FROM dbo.HostLogs
    ORDER BY id DESC
    OFFSET ? ROWS FETCH NEXT ? ROWS ONLY
    """
    rows = fetch_all(sql, [offset, limit])
    return [
        HostLogRow(
            id=int(r["id"]),
            result=str(r.get("result") or ""),
            content=(None if r.get("content") is None else str(r.get("content"))),
            create_time=r.get("create_time"),
            event_hash=(None if r.get("event_hash") is None else str(r.get("event_hash"))),
        )
        for r in rows
    ]


def get_hostlog_by_id(log_id: int) -> HostLogRow | None:
    sql = """
    SELECT id, result, content, create_time, event_hash
    FROM dbo.HostLogs
    WHERE id = ?
    """
    r = fetch_one(sql, [log_id])
    if not r:
        return None
    return HostLogRow(
        id=int(r["id"]),
        result=str(r.get("result") or ""),
        content=(None if r.get("content") is None else str(r.get("content"))),
        create_time=r.get("create_time"),
        event_hash=(None if r.get("event_hash") is None else str(r.get("event_hash"))),
    )


def count_hostlogs() -> int:
    r = fetch_one("SELECT COUNT(1) AS total FROM dbo.HostLogs")
    return int(r["total"]) if r and r.get("total") is not None else 0


def parse_result_json(result_text: str) -> dict[str, Any]:
    """
    将 HostLogs.result (JSON 字符串) 解析成 dict。
    解析失败时返回空 dict，避免页面渲染报错。
    """
    if not result_text:
        return {}
    try:
        obj = json.loads(result_text)
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}