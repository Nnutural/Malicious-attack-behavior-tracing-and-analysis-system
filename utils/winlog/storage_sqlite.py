"""主机日志 SQLite 本地存储。"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = Path("utils/winlog/.state/winlog_events.sqlite")


def _connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str | Path = DEFAULT_DB_PATH) -> Path:
    """初始化 SQLite 数据库。"""
    path = Path(db_path)
    with _connect(path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS winlog_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_hash TEXT UNIQUE,
                timestamp TEXT NOT NULL,
                host_ip TEXT NOT NULL,
                event_type TEXT NOT NULL,
                raw_id TEXT NOT NULL,
                description TEXT NOT NULL,
                data_source TEXT NOT NULL,
                entities_json TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_winlog_timestamp ON winlog_events(timestamp)"
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_winlog_host ON winlog_events(host_ip)")
    return path


def _event_hash(event: dict[str, Any]) -> str:
    payload = json.dumps(event, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def save_host_logs(events: Iterable[dict], db_path: str | Path = DEFAULT_DB_PATH) -> int:
    """保存归一化主机日志到 SQLite。"""
    path = init_db(db_path)
    inserted = 0
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with _connect(path) as conn:
        for event in events:
            try:
                event_hash = _event_hash(event)
                entities_json = json.dumps(
                    event.get("entities", {}), ensure_ascii=False, sort_keys=True
                )
                raw_json = json.dumps(event, ensure_ascii=False, sort_keys=True, indent=2)
                cursor = conn.execute(
                    """
                    INSERT OR IGNORE INTO winlog_events (
                        event_hash, timestamp, host_ip, event_type, raw_id,
                        description, data_source, entities_json, raw_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event_hash,
                        event.get("timestamp", ""),
                        event.get("host_ip", ""),
                        event.get("event_type", ""),
                        event.get("raw_id", ""),
                        event.get("description", ""),
                        event.get("data_source", ""),
                        entities_json,
                        raw_json,
                        now,
                    ),
                )
                if cursor.rowcount > 0:
                    inserted += 1
            except Exception as exc:
                logger.warning("写入 SQLite 失败: %s", exc)
        conn.commit()
    return inserted


def count_host_logs(db_path: str | Path = DEFAULT_DB_PATH) -> int:
    """统计已保存的日志数量。"""
    path = init_db(db_path)
    with _connect(path) as conn:
        row = conn.execute("SELECT COUNT(*) AS total FROM winlog_events").fetchone()
    return int(row["total"]) if row else 0


def fetch_host_logs(
    db_path: str | Path = DEFAULT_DB_PATH,
    *,
    offset: int = 0,
    limit: int = 50,
) -> list[dict]:
    """分页读取日志事件（包含 id 与 event）。"""
    path = init_db(db_path)
    with _connect(path) as conn:
        rows = conn.execute(
            """
            SELECT id, raw_json
            FROM winlog_events
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        ).fetchall()
    results: list[dict] = []
    for row in rows:
        try:
            event = json.loads(row["raw_json"])
        except json.JSONDecodeError:
            event = {}
        results.append({"id": row["id"], "event": event})
    return results


def fetch_host_log_by_id(db_path: str | Path, log_id: int) -> dict | None:
    """按 ID 读取单条日志事件。"""
    path = init_db(db_path)
    with _connect(path) as conn:
        row = conn.execute(
            "SELECT id, raw_json FROM winlog_events WHERE id = ?",
            (log_id,),
        ).fetchone()
    if not row:
        return None
    try:
        event = json.loads(row["raw_json"])
    except json.JSONDecodeError:
        event = {}
    return {"id": row["id"], "event": event}
