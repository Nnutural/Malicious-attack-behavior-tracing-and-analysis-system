"""
溯源分析编排层（修复版）：
- 不再依赖已删除的 Attack_Provenance.py
- real 模式从 SecurityTraceDB.dbo.AttackReports 读取报告
- vis_graph 优先从 Neo4j GraphSerializer 获取 scenario_topology
"""

from __future__ import annotations

import time
from typing import Any

from utils.trace.Graph_Serializer import GraphSerializer
from utils.trace.service.attack_reports_store import get_latest_attack_reports, parse_report_json

NEO4J_URI = "bolt://10.21.211.11:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "00000000"


class TracebackService:
    def __init__(self) -> None:
        self._cache_report: list[dict] | None = None
        self._cache_ts: float = 0.0
        self._cache_ttl_sec: int = 60

        self._serializer = GraphSerializer(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD)

    def get_high_alerts(self) -> list[dict]:
        """
        真实模式下：用 AttackReports 映射“High 告警列表”
        （因为 Attack_Provenance 已删除）
        """
        rows = get_latest_attack_reports(limit=30, confidence="High")
        items: list[dict] = []
        for r in rows:
            items.append(
                {
                    "id": r.get("scenario_id"),
                    "victim_ip": r.get("victim_ip"),
                    "timestamp_start": (r.get("start_time") or r.get("created_at") or ""),
                    "technique": (r.get("attribution_name") or "Attack Scenario"),
                }
            )
        return items

    def analyze_full(self, *, use_cache: bool = True) -> list[dict]:
        now = time.time()
        if use_cache and self._cache_report is not None and (now - self._cache_ts) < self._cache_ttl_sec:
            return self._cache_report

        rows = get_latest_attack_reports(limit=10, confidence=None)
        report = [self._convert_attack_report_row_to_traceback_item(r) for r in rows]

        self._cache_report = report
        self._cache_ts = now
        return report

    def _convert_attack_report_row_to_traceback_item(self, row: dict[str, Any]) -> dict[str, Any]:
        scenario_id = str(row.get("scenario_id") or "")
        victim_ip = str(row.get("victim_ip") or "")
        report_obj = parse_report_json(row.get("report_json"))

        attack_chain = report_obj.get("attack_chain") or []
        trigger_technique = ""
        if isinstance(attack_chain, list) and attack_chain:
            trigger_technique = str(attack_chain[-1])

        rca = report_obj.get("root_cause_analysis") or {}
        infra = report_obj.get("infrastructure") or {}

        paths: dict[str, Any] = {
            "process_tree": {
                "root_process": (rca.get("root_process") or rca.get("root_name") or ""),
                "root_cmd": rca.get("evidence") or "",
                "execution_chain": [],
            },
            "lateral_source": [],
            "exfiltration": [],
        }

        intruder_ip = rca.get("intruder_ip")
        if intruder_ip:
            paths["lateral_source"] = [
                {
                    "source_ip": intruder_ip,
                    "compromised_user": rca.get("user") or "",
                    "logon_time": row.get("start_time") or "",
                }
            ]

        attacker_profile = {
            "malware_hashes": infra.get("hashes") or [],
            "c2_domains": infra.get("domains") or [],
            "infrastructure_intelligence": [],
            "suspected_apt": [],
        }

        attribution = report_obj.get("attribution") or {}
        attr_type = attribution.get("type")

        # 允许 Known APT 和 Suspected Group 都进行展示
        if attribution and attr_type in ["Known APT", "Suspected Group"]:
            best = (attribution.get("result") or {}).get("best_match") or "Unknown Cluster"
            score = (attribution.get("result") or {}).get("confidence_score") or 0

            # 如果是疑似团伙，名字可能是一串 ID，我们可以加个前缀让它好读一点
            display_name = best
            if attr_type == "Suspected Group":
                display_name = f"Unidentified Cluster ({best[:8]})"

            attacker_profile["suspected_apt"] = [{"group": display_name, "similarity_score": score}]

        # 简化 timeline：用 attack_chain 做一个演示时间线
        timeline = []
        for idx, tech in enumerate(attack_chain[:10] if isinstance(attack_chain, list) else []):
            timeline.append(
                {
                    "time": row.get("start_time") or "",
                    "source": "attack_chain",
                    "event_type": "technique",
                    "summary": f"Stage {idx+1}: {tech}",
                    "raw": {"technique": tech},
                }
            )

        return {
            "alert_id": scenario_id,
            "victim_ip": victim_ip,
            "trigger_technique": trigger_technique or (row.get("attribution_name") or "Attack Scenario"),
            "paths": paths,
            "attacker_profile": attacker_profile,
            "timeline": timeline,
        }

    def build_vis_graph(self, report_item: dict) -> dict[str, Any]:
        """
        优先从 Neo4j 取 scenario_topology（需要 scenario_id 已写回 AttackEvent.scenario_id）
        """
        sid = str(report_item.get("alert_id") or "")
        try:
            data = self._serializer.get_scenario_topology(sid)
            if data and data.get("nodes"):
                return data
        except Exception:
            pass
        # fallback: 空图
        return {"nodes": [], "edges": []}