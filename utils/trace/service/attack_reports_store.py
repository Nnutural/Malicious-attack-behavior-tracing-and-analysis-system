from __future__ import annotations

import json
from typing import Any

from utils.db.db import fetch_all, fetch_one, execute


def get_latest_attack_reports(limit: int = 10, confidence: str | None = None) -> list[dict[str, Any]]:
    if confidence:
        sql = """
        SELECT TOP (?) *
        FROM dbo.AttackReports
        WHERE confidence = ?
        ORDER BY created_at DESC
        """
        return fetch_all(sql, [limit, confidence])

    sql = """
    SELECT TOP (?) *
    FROM dbo.AttackReports
    ORDER BY created_at DESC
    """
    return fetch_all(sql, [limit])


def parse_report_json(text: Any) -> dict[str, Any]:
    if not text:
        return {}
    if isinstance(text, dict):
        return text
    try:
        obj = json.loads(str(text))
        return obj if isinstance(obj, dict) else {"_raw": obj}
    except Exception:
        return {}