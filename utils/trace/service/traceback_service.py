"""
溯源分析编排层：
- 对接 Attack_Provenance.AttackProvenanceAnalyzer
- 生成页面需要的：
  - high_alerts
  - full report
  - 单条告警的 vis-network 图数据
"""
from __future__ import annotations

import time
from typing import Any

from utils.trace.Attack_Provenance import AttackProvenanceAnalyzer


NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "00000000"


class TracebackService:
    def __init__(self) -> None:
        self._cache_report: list[dict] | None = None
        self._cache_ts: float = 0.0
        self._cache_ttl_sec: int = 90  # 防止频繁打 VT / Neo4j

    def get_high_alerts(self) -> list[dict]:
        analyzer = AttackProvenanceAnalyzer(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD)
        try:
            return analyzer._get_high_confidence_events()
        finally:
            analyzer.close()

    def analyze_full(self, *, use_cache: bool = True) -> list[dict]:
        now = time.time()
        if use_cache and self._cache_report is not None and (now - self._cache_ts) < self._cache_ttl_sec:
            return self._cache_report

        analyzer = AttackProvenanceAnalyzer(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD)
        try:
            report = analyzer.run_full_analysis()
        finally:
            analyzer.close()

        self._cache_report = report
        self._cache_ts = now
        return report

    def build_vis_graph(self, report_item: dict) -> dict[str, Any]:
        """
        把单条 report 转成 vis-network {nodes, edges}。
        MVP：用“能读懂”的链路，不追求完全还原 Neo4j 子图。
        """
        nodes: list[dict] = []
        edges: list[dict] = []
        node_ids: set[str] = set()

        def add_node(node_id: str, label: str, group: str, **extra):
            if not node_id or node_id in node_ids:
                return
            node_ids.add(node_id)
            obj = {"id": node_id, "label": label, "group": group}
            obj.update(extra)
            nodes.append(obj)

        def add_edge(src: str, dst: str, label: str):
            if not src or not dst:
                return
            edges.append({"from": src, "to": dst, "label": label, "arrows": "to"})

        alert_id = str(report_item.get("alert_id") or "")
        victim_ip = str(report_item.get("victim_ip") or "")
        tech = str(report_item.get("trigger_technique") or "")

        add_node(alert_id, f"AttackEvent\\n{alert_id[:8]}", "AttackEvent", raw=report_item)
        if tech:
            tech_id = f"tech:{tech}"
            add_node(tech_id, tech, "Technique")
            add_edge(alert_id, tech_id, "IS_TYPE")

        if victim_ip:
            v_id = f"ip:{victim_ip}"
            add_node(v_id, victim_ip, "VictimIP")
            add_edge(alert_id, v_id, "TARGET")

        paths = report_item.get("paths") or {}

        # 1) 进程链
        pt = paths.get("process_tree")
        if isinstance(pt, dict):
            root = str(pt.get("root_process") or "unknown_root")
            root_id = f"proc:{victim_ip}:{root}:root"
            add_node(root_id, f"{root}", "Process", cmd=pt.get("root_cmd"), pid=pt.get("root_pid"))
            add_edge(alert_id, root_id, "TRIGGER_CONTEXT")

            chain = pt.get("execution_chain") or []
            prev = root_id
            for idx, name in enumerate(chain):
                if not name:
                    continue
                pid = f"proc:{victim_ip}:{name}:{idx}"
                add_node(pid, str(name), "Process")
                add_edge(prev, pid, "Spawn")
                prev = pid

        # 2) 横向移动来源
        lateral = paths.get("lateral_source")
        if isinstance(lateral, list):
            for item in lateral:
                src_ip = str(item.get("source_ip") or "")
                user = str(item.get("compromised_user") or "")
                if src_ip:
                    src_id = f"ip:{src_ip}"
                    add_node(src_id, src_ip, "SourceIP")
                    if victim_ip:
                        add_edge(src_id, f"ip:{victim_ip}", "Logon_Source")
                if user and victim_ip:
                    user_id = f"user:{victim_ip}:{user}"
                    add_node(user_id, user, "User", logon_time=item.get("logon_time"))
                    add_edge(user_id, f"ip:{victim_ip}", "Logon")

        # 3) 外传
        exf = paths.get("exfiltration")
        if isinstance(exf, list):
            for item in exf:
                f = str(item.get("sensitive_file") or "")
                p = str(item.get("leaking_process") or "")
                dst = str(item.get("destination_ip") or "")
                if f:
                    fid = f"file:{victim_ip}:{f}"
                    add_node(fid, f, "File")
                else:
                    fid = ""
                if p:
                    pid = f"proc:{victim_ip}:{p}:exfil"
                    add_node(pid, p, "Process")
                else:
                    pid = ""
                if dst:
                    did = f"ip:{dst}"
                    add_node(did, dst, "ExternalIP")
                else:
                    did = ""

                if pid and fid:
                    add_edge(pid, fid, "Read")
                if pid and did:
                    add_edge(pid, did, "Connect")

        # 4) 域名 & 情报（先连 AttackEvent，MVP）
        profile = report_item.get("attacker_profile") or {}
        for d in profile.get("c2_domains") or []:
            d = str(d or "").strip()
            if not d:
                continue
            did = f"domain:{d}"
            add_node(did, d, "Domain")
            add_edge(alert_id, did, "C2")

        return {"nodes": nodes, "edges": edges}