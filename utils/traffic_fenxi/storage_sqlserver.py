"""
NetworkTraffic (dbo.NetworkTraffic) SQL Server 存储层（v2）
字段（建议你表结构升级后保持一致）：
- id INT IDENTITY PRIMARY KEY
- result NVARCHAR(MAX)
- content NVARCHAR(MAX)
- create_time DATETIME2 DEFAULT(sysdatetime())
- event_hash VARCHAR(64) NULL（去重）
- host_name NVARCHAR(255) NULL（采集点/传感器/iface）
- event_time_utc DATETIME2 NULL（从 result.timestamp 解析）
"""
from __future__ import annotations

import json
import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from utils.db.db import execute, fetch_all, fetch_one


@dataclass
class NetworkTrafficRow:
    id: int
    result: str
    content: str | None
    create_time: Any | None = None
    event_hash: str | None = None
    host_name: str | None = None
    event_time_utc: Any | None = None


def parse_result_json(result_text: str) -> dict[str, Any]:
    if not result_text:
        return {}
    try:
        obj = json.loads(result_text)
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def generate_event_hash(result_dict: dict) -> str:
    sorted_json = json.dumps(result_dict, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(sorted_json.encode("utf-8")).hexdigest()


def _parse_event_time_utc(timestamp_str: str | None) -> str | None:
    """
    将 result.timestamp（ISO8601 like: 2026-01-14T13:25:14Z）转换为 SQL 可接受的 datetime 字符串
    返回：'YYYY-MM-DD HH:MM:SS' 或 None
    """
    if not timestamp_str:
        return None
    text = str(timestamp_str).strip()
    if not text:
        return None
    try:
        # 兼容带 Z
        if text.endswith("Z"):
            dt = datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ")
        else:
            # 兜底：尽量解析到秒
            dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return None


def insert_networktraffic(
    *,
    result_json: str,
    content: str | None,
    event_hash: str | None = None,
    host_name: str | None = None,
    event_time_utc: str | None = None,
    conn_str: str | None = None,
) -> int:
    sql = """
    INSERT INTO dbo.NetworkTraffic (result, content, event_hash, host_name, event_time_utc)
    VALUES (?, ?, ?, ?, ?)
    """
    return execute(sql, [result_json, content, event_hash, host_name, event_time_utc], conn_str)


def insert_networktraffic_from_dict(
    *,
    result_dict: dict[str, Any],
    content: str | None,
    host_name: str | None,
    conn_str: str | None = None,
) -> dict[str, int]:
    """
    统一入口：自动生成 event_hash + event_time_utc，利用唯一索引去重。
    返回：{inserted, skipped, errors}
    """
    inserted = 0
    skipped = 0
    errors = 0

    try:
        event_hash = generate_event_hash(result_dict)
        event_time_utc = _parse_event_time_utc(result_dict.get("timestamp"))
        result_json = json.dumps(result_dict, ensure_ascii=False)

        try:
            insert_networktraffic(
                result_json=result_json,
                content=content,
                event_hash=event_hash,
                host_name=host_name,
                event_time_utc=event_time_utc,
                conn_str=conn_str,
            )
            inserted += 1
        except Exception:
            # 很大概率是唯一索引冲突（去重），这里直接算 skipped
            skipped += 1

    except Exception:
        errors += 1

    return {"inserted": inserted, "skipped": skipped, "errors": errors}


def list_networktraffic(*, offset: int, limit: int, host_name: str | None = None, conn_str: str | None = None) -> list[NetworkTrafficRow]:
    filters = []
    params: list[Any] = []
    if host_name:
        filters.append("host_name = ?")
        params.append(host_name)

    where_clause = ("WHERE " + " AND ".join(filters)) if filters else ""
    sql = f"""
    SELECT id, result, content, create_time, event_hash, host_name, event_time_utc
    FROM dbo.NetworkTraffic
    {where_clause}
    ORDER BY id DESC
    OFFSET ? ROWS FETCH NEXT ? ROWS ONLY
    """
    params.extend([offset, limit])
    rows = fetch_all(sql, params, conn_str)
    out: list[NetworkTrafficRow] = []
    for r in rows:
        out.append(
            NetworkTrafficRow(
                id=int(r["id"]),
                result=str(r.get("result") or ""),
                content=None if r.get("content") is None else str(r.get("content")),
                create_time=r.get("create_time"),
                event_hash=None if r.get("event_hash") is None else str(r.get("event_hash")),
                host_name=None if r.get("host_name") is None else str(r.get("host_name")),
                event_time_utc=r.get("event_time_utc"),
            )
        )
    return out


def count_networktraffic(*, host_name: str | None = None, conn_str: str | None = None) -> int:
    filters = []
    params: list[Any] = []
    if host_name:
        filters.append("host_name = ?")
        params.append(host_name)
    where_clause = ("WHERE " + " AND ".join(filters)) if filters else ""
    r = fetch_one(f"SELECT COUNT(1) AS total FROM dbo.NetworkTraffic {where_clause}", params=params, conn_str=conn_str)
    return int(r["total"]) if r and r.get("total") is not None else 0


def get_networktraffic_by_id(traffic_id: int, conn_str: str | None = None) -> NetworkTrafficRow | None:
    sql = """
    SELECT id, result, content, create_time, event_hash, host_name, event_time_utc
    FROM dbo.NetworkTraffic
    WHERE id = ?
    """
    r = fetch_one(sql, [traffic_id], conn_str)
    if not r:
        return None
    return NetworkTrafficRow(
        id=int(r["id"]),
        result=str(r.get("result") or ""),
        content=None if r.get("content") is None else str(r.get("content")),
        create_time=r.get("create_time"),
        event_hash=None if r.get("event_hash") is None else str(r.get("event_hash")),
        host_name=None if r.get("host_name") is None else str(r.get("host_name")),
        event_time_utc=r.get("event_time_utc"),
    )