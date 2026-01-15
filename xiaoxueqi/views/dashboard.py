"""
仪表盘视图（已移除“分析引擎控制”相关逻辑）：
- KPI：HostLogs / HostBehaviors / NetworkTraffic / AttackReports
- 数据新鲜度：MAX(create_time/created_at)
- 最近报告：dbo.AttackReports TOP N（解析 report_json 生成摘要）

注意：dashboard.html 依赖 freshness/recent_reports 变量。
"""

from __future__ import annotations

import logging

from flask import Blueprint, jsonify, render_template

from utils.dashboard.dashboard_service import get_dashboard_data

bp = Blueprint("dashboard", __name__)
logger = logging.getLogger(__name__)


@bp.route("/", methods=["GET"])
def index():
    data = get_dashboard_data(recent_limit=10)
    return render_template(
        "dashboard.html",
        stats=data["stats"],
        freshness=data["freshness"],
        recent_reports=data["recent_reports"],
    )


@bp.route("/api/overview", methods=["GET"])
def api_overview():
    """
    可选：给前端做自动刷新用（不包含任何引擎 start/stop/status）。
    """
    try:
        data = get_dashboard_data(recent_limit=10)
        return jsonify({"ok": True, **data})
    except Exception as exc:
        logger.warning("dashboard api_overview failed: %s", exc)
        return jsonify({"ok": False, "error": str(exc)}), 500