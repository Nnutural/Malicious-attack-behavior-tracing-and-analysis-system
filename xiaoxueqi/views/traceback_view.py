"""溯源分析视图"""
from __future__ import annotations

from flask import Blueprint, jsonify, render_template, request

from utils.trace.service.traceback_service import TracebackService


bp = Blueprint("traceback", __name__)
svc = TracebackService()


@bp.route("/", methods=["GET"])
def index():
    return render_template("traceback.html")


@bp.route("/api/high_alerts", methods=["GET"])
def api_high_alerts():
    try:
        items = svc.get_high_alerts()
        return jsonify({"ok": True, "mode": "real", "items": items})
    except Exception as exc:
        # 没装 neo4j 或没启动时，让用户前端可以切 mock
        return jsonify({"ok": False, "mode": "real", "error": str(exc), "items": []}), 500


@bp.route("/api/analyze", methods=["POST"])
def api_analyze():
    payload = request.get_json(silent=True) or {}
    mock_mode = bool(payload.get("mock_mode", True))  # 没 neo4j 时默认 true
    use_cache = bool(payload.get("use_cache", True))

    try:
        report = svc.analyze_full(use_cache=use_cache)
        enriched = []
        for item in report:
            item2 = dict(item)
            item2["vis_graph"] = svc.build_vis_graph(item2)
            enriched.append(item2)
        return jsonify({"ok": True, "mode": "real", "report": enriched})
    except Exception as exc:
        return jsonify({"ok": False, "mode": "real", "error": str(exc)}), 500