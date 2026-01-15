"""
Dashboard SQL Server 存储层（只放 SQL 查询）。

依赖：utils.db.db（pyodbc 简单封装）
"""

from __future__ import annotations

from typing import Any

from utils.db.db import fetch_one, fetch_all


def _safe_int(val: Any) -> int:
    try:
        return int(val)
    except Exception:
        return 0


def count_table(table: str) -> int:
    """
    通用 count。table 必须来自代码内部白名单调用，禁止传入用户输入。
    """
    row = fetch_one(f"SELECT COUNT(1) AS total FROM dbo.{table}")
    return _safe_int(row["total"]) if row else 0


def get_latest_time(table: str, time_col: str = "create_time") -> str | None:
    """
    获取某表最新时间（MAX）。
    """
    row = fetch_one(f"SELECT MAX({time_col}) AS latest FROM dbo.{table}")
    if not row:
        return None
    v = row.get("latest")
    return None if v is None else str(v)


def list_recent_attack_reports(limit: int = 10) -> list[dict]:
    """
    最近 AttackReports 列表（用于仪表盘表格）。
    读取 report_json 是为了给 dashboard 做更好的摘要（attack_chain / root_cause 等）。
    """
    sql = """
    SELECT TOP (?)
        id, scenario_id, victim_ip, attacker_ip,
        start_time, end_time,
        confidence, attribution_type, attribution_name,
        created_at, report_json
    FROM dbo.AttackReports
    ORDER BY created_at DESC
    """
    return fetch_all(sql, [int(limit)])