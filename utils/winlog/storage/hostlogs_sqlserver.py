"""
HostLogs (dbo.HostLogs) SQL Server 存储层。

表字段假设：
- id INT IDENTITY PRIMARY KEY
- result NVARCHAR(MAX)   -- 归一化后的 dict（JSON 字符串）
- content NVARCHAR(MAX)  -- 原始完整日志（建议存 XML 或 Raw JSON 字符串）
- create_time DATETIME2 DEFAULT(sysdatetime())
- event_hash VARCHAR(64) NULL      -- 用于去重（建议建唯一索引）
- host_name NVARCHAR(255) NULL     -- 新增：主机名/ComputerName（用于筛选）

建议建立唯一索引（一次性执行）：
CREATE UNIQUE INDEX UX_HostLogs_event_hash
ON dbo.HostLogs(event_hash)
WHERE event_hash IS NOT NULL;

建议为 host_name 建普通索引：
CREATE INDEX IX_HostLogs_host_name
ON dbo.HostLogs(host_name);
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
    host_name: str | None = None


def insert_hostlog(*, result_json: str, content: str | None, event_hash: str, host_name: str | None) -> int:
    """
    插入一条 HostLogs 记录。
    - create_time 使用数据库默认 sysdatetime()。
    """
    sql = """
    INSERT INTO dbo.HostLogs (result, content, event_hash, host_name)
    VALUES (?, ?, ?, ?)
    """
    return execute(sql, [result_json, content, event_hash, host_name])


def list_hostlogs(*, offset: int, limit: int, host_name: str | None = None) -> list[HostLogRow]:
    """
    分页查询（最新在前）。
    支持按 host_name 精确筛选：WHERE host_name = ?
    """
    if host_name:
        sql = """
        SELECT id, result, content, create_time, event_hash, host_name
        FROM dbo.HostLogs
        WHERE host_name = ?
        ORDER BY id DESC
        OFFSET ? ROWS FETCH NEXT ? ROWS ONLY
        """
        params = [host_name, offset, limit]
    else:
        sql = """
        SELECT id, result, content, create_time, event_hash, host_name
        FROM dbo.HostLogs
        ORDER BY id DESC
        OFFSET ? ROWS FETCH NEXT ? ROWS ONLY
        """
        params = [offset, limit]

    rows = fetch_all(sql, params)
    return [
        HostLogRow(
            id=int(r["id"]),
            result=str(r.get("result") or ""),
            content=(None if r.get("content") is None else str(r.get("content"))),
            create_time=r.get("create_time"),
            event_hash=(None if r.get("event_hash") is None else str(r.get("event_hash"))),
            host_name=(None if r.get("host_name") is None else str(r.get("host_name"))),
        )
        for r in rows
    ]


def get_hostlog_by_id(log_id: int) -> HostLogRow | None:
    sql = """
    SELECT id, result, content, create_time, event_hash, host_name
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
        host_name=(None if r.get("host_name") is None else str(r.get("host_name"))),
    )


def count_hostlogs(host_name: str | None = None) -> int:
    if host_name:
        r = fetch_one("SELECT COUNT(1) AS total FROM dbo.HostLogs WHERE host_name = ?", [host_name])
    else:
        r = fetch_one("SELECT COUNT(1) AS total FROM dbo.HostLogs")
    return int(r["total"]) if r and r.get("total") is not None else 0


def list_distinct_host_names(limit: int = 200) -> list[str]:
    """
    返回出现过的 host_name 列表（用于前端下拉）。
    limit 防止数据量很大时下拉过长。
    """
    sql = """
    SELECT TOP (?) host_name
    FROM dbo.HostLogs
    WHERE host_name IS NOT NULL AND LTRIM(RTRIM(host_name)) <> ''
    GROUP BY host_name
    ORDER BY host_name ASC
    """
    rows = fetch_all(sql, [limit])
    return [str(r["host_name"]) for r in rows if r.get("host_name")]


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