"""
HostBehaviors (dbo.HostBehaviors) SQL Server 存储层。

表字段：
- id INT IDENTITY PRIMARY KEY
- result NVARCHAR(MAX) NOT NULL
- content NVARCHAR(MAX) NULL
- create_time DATETIME2 DEFAULT(sysdatetime())
- event_hash VARCHAR(64) NULL（唯一索引去重）
- host_name NVARCHAR(255) NULL
- event_time_utc DATETIME2 NULL
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from utils.db.db import execute, fetch_all, fetch_one


@dataclass
class HostBehaviorRow:
    id: int
    result: str
    content: str | None
    create_time: Any | None = None
    event_hash: str | None = None
    host_name: str | None = None
    event_time_utc: Any | None = None


def insert_hostbehavior(
    *,
    result_json: str,
    content: str | None,
    event_hash: str,
    host_name: str | None,
    event_time_utc: Any | None,
) -> int:
    sql = """
    INSERT INTO dbo.HostBehaviors (result, content, event_hash, host_name, event_time_utc)
    VALUES (?, ?, ?, ?, ?)
    """
    return execute(sql, [result_json, content, event_hash, host_name, event_time_utc])


def list_hostbehaviors(*, offset: int, limit: int, host_name: str | None = None) -> list[HostBehaviorRow]:
    if host_name:
        sql = """
        SELECT id, result, content, create_time, event_hash, host_name, event_time_utc
        FROM dbo.HostBehaviors
        WHERE host_name = ?
        ORDER BY id DESC
        OFFSET ? ROWS FETCH NEXT ? ROWS ONLY
        """
        params = [host_name, offset, limit]
    else:
        sql = """
        SELECT id, result, content, create_time, event_hash, host_name, event_time_utc
        FROM dbo.HostBehaviors
        ORDER BY id DESC
        OFFSET ? ROWS FETCH NEXT ? ROWS ONLY
        """
        params = [offset, limit]

    rows = fetch_all(sql, params)
    return [
        HostBehaviorRow(
            id=int(r["id"]),
            result=str(r.get("result") or ""),
            content=(None if r.get("content") is None else str(r.get("content"))),
            create_time=r.get("create_time"),
            event_hash=(None if r.get("event_hash") is None else str(r.get("event_hash"))),
            host_name=(None if r.get("host_name") is None else str(r.get("host_name"))),
            event_time_utc=r.get("event_time_utc"),
        )
        for r in rows
    ]


def count_hostbehaviors(host_name: str | None = None) -> int:
    if host_name:
        r = fetch_one("SELECT COUNT(1) AS total FROM dbo.HostBehaviors WHERE host_name = ?", [host_name])
    else:
        r = fetch_one("SELECT COUNT(1) AS total FROM dbo.HostBehaviors")
    return int(r["total"]) if r and r.get("total") is not None else 0


def list_distinct_host_names(limit: int = 200) -> list[str]:
    sql = """
    SELECT TOP (?) host_name
    FROM dbo.HostBehaviors
    WHERE host_name IS NOT NULL AND LTRIM(RTRIM(host_name)) <> ''
    GROUP BY host_name
    ORDER BY host_name ASC
    """
    rows = fetch_all(sql, [limit])
    return [str(r["host_name"]) for r in rows if r.get("host_name")]


def get_hostbehavior_by_id(row_id: int) -> HostBehaviorRow | None:
    sql = """
    SELECT id, result, content, create_time, event_hash, host_name, event_time_utc
    FROM dbo.HostBehaviors
    WHERE id = ?
    """
    r = fetch_one(sql, [row_id])
    if not r:
        return None
    return HostBehaviorRow(
        id=int(r["id"]),
        result=str(r.get("result") or ""),
        content=(None if r.get("content") is None else str(r.get("content"))),
        create_time=r.get("create_time"),
        event_hash=(None if r.get("event_hash") is None else str(r.get("event_hash"))),
        host_name=(None if r.get("host_name") is None else str(r.get("host_name"))),
        event_time_utc=r.get("event_time_utc"),
    )


def parse_result_json(result_text: str) -> dict[str, Any]:
    if not result_text:
        return {}
    try:
        obj = json.loads(result_text)
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}