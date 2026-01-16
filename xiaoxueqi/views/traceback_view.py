"""溯源分析视图"""
from __future__ import annotations

from flask import Blueprint, jsonify, render_template, request

from utils.trace.service.traceback_service import TracebackService
from utils.trace.LLM_Reporter import LLMReporter

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


llm_reporter = LLMReporter()  # 实例化


@bp.route("/api/generate_report_ai", methods=["POST"])
def api_generate_report_ai():
    """
    新接口：接收前端传来的 report_item JSON，交给 AI 润色
    """
    try:
        payload = request.get_json(silent=True) or {}
        report_data = payload.get("report_data")

        if not report_data:
            return jsonify({"ok": False, "error": "No data provided"}), 400

        # 调用 AI 生成
        markdown_text = llm_reporter.generate_narrative_report(report_data)

        return jsonify({"ok": True, "data": markdown_text})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500