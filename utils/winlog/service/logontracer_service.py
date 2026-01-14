"""LogonTracer aggregation helpers (SQL Server -> graph/timeline/sessions)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from utils.db.db import fetch_all
from utils.winlog.session_rebuild import rebuild_logon_sessions

DEFAULT_RANGE_HOURS = 24
MAX_RANGE_DAYS = 30


def _parse_iso8601_utc(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _format_zulu(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _normalize_text(value: Any) -> str:
    return str(value or "").strip().lower()


def _resolve_time_range(start: str | None, end: str | None) -> tuple[datetime, datetime]:
    end_dt = _parse_iso8601_utc(end) if end else datetime.now(timezone.utc)
    if end_dt is None:
        raise ValueError("end time format invalid")
    start_dt = _parse_iso8601_utc(start) if start else (end_dt - timedelta(hours=DEFAULT_RANGE_HOURS))
    if start_dt is None:
        raise ValueError("start time format invalid")
    if start_dt > end_dt:
        raise ValueError("start time is after end time")
    if end_dt - start_dt > timedelta(days=MAX_RANGE_DAYS):
        raise ValueError("time range exceeds max window")
    return start_dt, end_dt


def _to_db_datetime(dt: datetime) -> datetime:
    return dt.replace(tzinfo=None)


def _bucket_floor(dt: datetime, bucket: str) -> datetime:
    if bucket == "day":
        return dt.replace(hour=0, minute=0, second=0, microsecond=0)
    return dt.replace(minute=0, second=0, microsecond=0)


def _event_success(event: dict[str, Any]) -> bool:
    raw_id = str(event.get("raw_id") or "")
    event_type = str(event.get("event_type") or "")
    return raw_id == "4624" or event_type == "user_logon"


def _event_fail(event: dict[str, Any]) -> bool:
    raw_id = str(event.get("raw_id") or "")
    event_type = str(event.get("event_type") or "")
    return raw_id == "4625" or event_type == "user_logon_failed"


def load_hostlogs(
    *,
    conn_str: str,
    start_dt: datetime,
    end_dt: datetime,
    host_names: list[str] | None = None,
) -> list[dict[str, Any]]:
    sql = """
    SELECT id, result, create_time, host_name
    FROM dbo.HostLogs
    WHERE create_time >= ? AND create_time <= ?
    """
    params: list[Any] = [_to_db_datetime(start_dt), _to_db_datetime(end_dt)]
    if host_names:
        placeholders = ", ".join("?" for _ in host_names)
        sql += f" AND host_name IN ({placeholders})"
        params.extend(host_names)
    return fetch_all(sql, params, conn_str)


@dataclass
class LogonTracerResult:
    graph: dict[str, Any]
    timeline: dict[str, Any]
    sessions: list[dict[str, Any]]
    events: list[dict[str, Any]]
    bucket: str


def build_logontracer_result(
    *,
    conn_str: str,
    start: str | None,
    end: str | None,
    user: str | None,
    src_ip: str | None,
    host_names: list[str] | None,
    bucket: str | None,
    progress_cb: Callable[[int, str], None] | None = None,
) -> LogonTracerResult:
    bucket = (bucket or "hour").lower()
    if bucket not in ("hour", "day"):
        bucket = "hour"

    start_dt, end_dt = _resolve_time_range(start, end)

    if progress_cb:
        progress_cb(10, "querying host logs")
    rows = load_hostlogs(conn_str=conn_str, start_dt=start_dt, end_dt=end_dt, host_names=host_names)

    if progress_cb:
        progress_cb(30, "parsing events")
    events = _extract_events(
        rows,
        start_dt=start_dt,
        end_dt=end_dt,
        user=user,
        src_ip=src_ip,
        host_names=host_names,
    )

    if progress_cb:
        progress_cb(55, "building graph")
    graph = build_graphs(events, split_by_host=False)

    if progress_cb:
        progress_cb(70, "building timeline")
    timeline = build_timeline(events, bucket=bucket)

    if progress_cb:
        progress_cb(85, "rebuilding sessions")
    sorted_events = sorted(events, key=lambda item: item.get("_dt") or datetime.min.replace(tzinfo=timezone.utc))
    sessions = rebuild_logon_sessions(sorted_events, strict=False)

    if progress_cb:
        progress_cb(100, "done")

    return LogonTracerResult(
        graph=graph,
        timeline=timeline,
        sessions=sessions,
        events=events,
        bucket=bucket,
    )


def _extract_events(
    rows: list[dict[str, Any]],
    *,
    start_dt: datetime,
    end_dt: datetime,
    user: str | None,
    src_ip: str | None,
    host_names: list[str] | None,
) -> list[dict[str, Any]]:
    user_norm = _normalize_text(user)
    src_norm = _normalize_text(src_ip)
    host_norms = [_normalize_text(name) for name in (host_names or []) if _normalize_text(name)]
    events: list[dict[str, Any]] = []

    for row in rows:
        result_text = row.get("result")
        if not result_text:
            continue
        try:
            event = json.loads(result_text)
        except Exception:
            continue
        if not isinstance(event, dict):
            continue

        raw_id = str(event.get("raw_id") or "")
        event_type = str(event.get("event_type") or "")
        if event_type not in ("user_logon", "user_logon_failed", "user_logoff") and raw_id not in ("4624", "4625", "4634", "4647"):
            continue

        timestamp = str(event.get("timestamp") or "")
        event_dt = _parse_iso8601_utc(timestamp)
        if event_dt is None:
            continue
        if event_dt < start_dt or event_dt > end_dt:
            continue

        host_ip = str(event.get("host_ip") or "")
        if not host_ip:
            continue

        entities = event.get("entities") or {}
        if not isinstance(entities, dict):
            entities = {}

        row_host = _normalize_text(row.get("host_name"))
        if host_norms:
            if row_host:
                if row_host not in host_norms:
                    continue
            elif _normalize_text(host_ip) not in host_norms:
                continue

        if user_norm:
            if user_norm not in _normalize_text(entities.get("user")):
                continue

        if src_norm:
            if src_norm not in _normalize_text(entities.get("src_ip")):
                continue

        events.append(
            {
                "timestamp": _format_zulu(event_dt),
                "host_ip": host_ip,
                "host_name": row.get("host_name"),
                "raw_id": raw_id,
                "event_type": event_type,
                "entities": entities,
                "description": str(event.get("description") or ""),
                "_dt": event_dt,
            }
        )

    return events


def build_graph(events: list[dict[str, Any]]) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[str, dict[str, Any]] = {}

    def touch_node(node_id: str, label: str, node_type: str, ts: datetime) -> None:
        node = nodes.get(node_id)
        if not node:
            node = {"id": node_id, "label": label, "type": node_type, "weight": 0, "last_seen": None}
            nodes[node_id] = node
        node["weight"] += 1
        last_seen = node.get("last_seen")
        if last_seen is None or ts > last_seen:
            node["last_seen"] = ts

    def touch_edge(edge_id: str, source: str, target: str, ts: datetime, success: bool, fail: bool) -> None:
        edge = edges.get(edge_id)
        if not edge:
            edge = {
                "id": edge_id,
                "source": source,
                "target": target,
                "success_count": 0,
                "fail_count": 0,
                "last_seen": None,
            }
            edges[edge_id] = edge
        if success:
            edge["success_count"] += 1
        if fail:
            edge["fail_count"] += 1
        last_seen = edge.get("last_seen")
        if last_seen is None or ts > last_seen:
            edge["last_seen"] = ts

    for event in events:
        ts = event.get("_dt")
        if not isinstance(ts, datetime):
            continue
        host_ip = str(event.get("host_ip") or "")
        if not host_ip:
            continue

        success = _event_success(event)
        fail = _event_fail(event)
        if not success and not fail:
            continue

        host_id = f"host:{host_ip}"
        touch_node(host_id, host_ip, "host", ts)

        entities = event.get("entities") or {}
        user = str(entities.get("user") or "")
        src_ip = str(entities.get("src_ip") or "")

        if src_ip:
            ip_id = f"ip:{src_ip}"
            touch_node(ip_id, src_ip, "ip", ts)
            edge_id = f"edge:{ip_id}->{host_id}"
            touch_edge(edge_id, ip_id, host_id, ts, success, fail)

        if user:
            user_id = f"user:{user}"
            touch_node(user_id, user, "user", ts)
            edge_id = f"edge:{user_id}->{host_id}"
            touch_edge(edge_id, user_id, host_id, ts, success, fail)

    node_list = []
    for node in nodes.values():
        last_seen = node.get("last_seen")
        node_list.append(
            {
                "data": {
                    "id": node["id"],
                    "label": node["label"],
                    "type": node["type"],
                    "weight": node["weight"],
                    "last_seen": _format_zulu(last_seen) if isinstance(last_seen, datetime) else None,
                }
            }
        )

    edge_list = []
    for edge in edges.values():
        last_seen = edge.get("last_seen")
        edge_list.append(
            {
                "data": {
                    "id": edge["id"],
                    "source": edge["source"],
                    "target": edge["target"],
                    "success_count": edge["success_count"],
                    "fail_count": edge["fail_count"],
                    "last_seen": _format_zulu(last_seen) if isinstance(last_seen, datetime) else None,
                }
            }
        )

    return {"elements": {"nodes": node_list, "edges": edge_list}}


def build_graphs(events: list[dict[str, Any]], *, split_by_host: bool) -> dict[str, Any]:
    if not split_by_host:
        return build_graph(events)

    groups: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        host_key = str(event.get("host_name") or event.get("host_ip") or "unknown")
        groups.setdefault(host_key, []).append(event)

    graphs = []
    for host_key in sorted(groups.keys()):
        elements = build_graph(groups[host_key]).get("elements", {})
        graphs.append({"host": host_key, "elements": elements})

    if len(graphs) == 1:
        return {"elements": graphs[0]["elements"], "graphs": graphs}
    return {"graphs": graphs}


def build_timeline(events: list[dict[str, Any]], *, bucket: str) -> dict[str, Any]:
    success_counts: dict[int, int] = {}
    fail_counts: dict[int, int] = {}

    for event in events:
        ts = event.get("_dt")
        if not isinstance(ts, datetime):
            ts = _parse_iso8601_utc(str(event.get("timestamp") or ""))
        if ts is None:
            continue
        success = _event_success(event)
        fail = _event_fail(event)
        if not success and not fail:
            continue
        bucket_dt = _bucket_floor(ts, bucket)
        epoch_ms = int(bucket_dt.timestamp() * 1000)
        if success:
            success_counts[epoch_ms] = success_counts.get(epoch_ms, 0) + 1
        if fail:
            fail_counts[epoch_ms] = fail_counts.get(epoch_ms, 0) + 1

    def build_series(counts: dict[int, int]) -> list[dict[str, Any]]:
        return [{"t": key, "v": counts[key]} for key in sorted(counts)]

    return {
        "bucket": bucket,
        "series": {
            "success": build_series(success_counts),
            "fail": build_series(fail_counts),
        },
    }


def serialize_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output = []
    for event in events:
        output.append(
            {
                "timestamp": event.get("timestamp"),
                "host_ip": event.get("host_ip"),
                "raw_id": event.get("raw_id"),
                "event_type": event.get("event_type"),
                "entities": event.get("entities") or {},
                "description": event.get("description") or "",
            }
        )
    return output
