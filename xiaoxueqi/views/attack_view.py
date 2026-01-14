from __future__ import annotations

import threading

from flask import Blueprint, jsonify, render_template, request

from utils.trace.Graph_Serializer import GraphSerializer
import utils.trace.main_pipeline as main_pipeline
from utils.trace.service.attack_reports_store import get_latest_attack_reports, parse_report_json
from utils.db.db import fetch_all, fetch_one

bp = Blueprint("attack", __name__)

NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = "00000000"

serializer = GraphSerializer(NEO4J_URI, NEO4J_USER, NEO4J_PASS)

_pipeline_thread: threading.Thread | None = None


@bp.route("/", methods=["GET"])
def index():
    return render_template("attack_chain.html")


@bp.route("/api/reports", methods=["GET"])
def api_reports():
    page = request.args.get("page", 1, type=int)
    page = max(page, 1)
    limit = request.args.get("limit", 10, type=int)
    limit = max(5, min(limit, 50))
    offset = (page - 1) * limit

    victim_ip = (request.args.get("ip") or "").strip() or None
    confidence = (request.args.get("confidence") or "").strip() or None

    filters = []
    params = []
    if victim_ip:
        filters.append("victim_ip = ?")
        params.append(victim_ip)
    if confidence:
        filters.append("confidence = ?")
        params.append(confidence)

    where_clause = ("WHERE " + " AND ".join(filters)) if filters else ""

    total_row = fetch_one(f"SELECT COUNT(1) AS total FROM dbo.AttackReports {where_clause}", params)
    total = int(total_row["total"]) if total_row else 0

    rows = fetch_all(
        f"""
        SELECT id, scenario_id, victim_ip, attacker_ip, start_time, end_time,
               confidence, attribution_type, attribution_name, created_at
        FROM dbo.AttackReports
        {where_clause}
        ORDER BY created_at DESC
        OFFSET ? ROWS FETCH NEXT ? ROWS ONLY
        """,
        params + [offset, limit],
    )
    return jsonify({"ok": True, "total": total, "page": page, "limit": limit, "data": rows})


@bp.route("/api/report/<scenario_id>", methods=["GET"])
def api_report_detail(scenario_id: str):
    row = fetch_one(
        """
        SELECT TOP 1 *
        FROM dbo.AttackReports
        WHERE scenario_id = ?
        ORDER BY created_at DESC
        """,
        [scenario_id],
    )
    if not row:
        return jsonify({"ok": False, "error": "Report not found"}), 404
    return jsonify({"ok": True, "row": row, "report": parse_report_json(row.get("report_json"))})


@bp.route("/api/graph/<scenario_id>/summary", methods=["GET"])
def api_graph_summary(scenario_id: str):
    try:
        data = serializer.get_attack_chain_summary(scenario_id)
        return jsonify({"ok": True, "data": data})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e), "data": {"nodes": [], "edges": []}}), 500


@bp.route("/api/graph/<scenario_id>/topology", methods=["GET"])
def api_graph_topology(scenario_id: str):
    try:
        data = serializer.get_scenario_topology(scenario_id)
        return jsonify({"ok": True, "data": data})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e), "data": {"nodes": [], "edges": []}}), 500


@bp.route("/api/system/status", methods=["GET"])
def api_system_status():
    global _pipeline_thread
    is_running = _pipeline_thread is not None and _pipeline_thread.is_alive()
    return jsonify({"ok": True, "status": "running" if is_running else "stopped"})


@bp.route("/api/system/start", methods=["POST"])
def api_system_start():
    global _pipeline_thread
    if _pipeline_thread is not None and _pipeline_thread.is_alive():
        return jsonify({"ok": False, "error": "任务已经在运行中"}), 400

    main_pipeline.STOP_FLAG = False
    _pipeline_thread = threading.Thread(target=main_pipeline.pipeline_loop, daemon=True)
    _pipeline_thread.start()
    return jsonify({"ok": True, "message": "分析引擎已启动"})


@bp.route("/api/system/stop", methods=["POST"])
def api_system_stop():
    main_pipeline.STOP_FLAG = True
    return jsonify({"ok": True, "message": "正在停止分析引擎（等待当前周期结束）"})