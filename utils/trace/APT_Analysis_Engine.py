import logging
import numpy as np
from neo4j import GraphDatabase
import json
import uuid
from collections import Counter
from utils.trace.Threat_Intel import VirusTotalEnricher
import os

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class APTAnalysisEngine:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        vt_key = os.getenv("VT_API_KEY", "ccccce76f24f200b35412471d447776e6cafd120c42cc2a44dc2ebd33f098532")
        self.ti_engine = VirusTotalEnricher(vt_key)

    def close(self):
        self.driver.close()

    def run_pipeline(self):
        """
        [主入口] 执行完整的 溯源 -> 特征提取 -> 匹配 -> 画像生成 流程
        """
        logging.info("启动 APT 溯源与归因分析引擎...")

        # 1. 提取完整的攻击场景链 (Attack Scenario Extraction)
        scenarios = self._extract_attack_scenarios()
        logging.info(f"提取到 {len(scenarios)} 个完整的攻击场景子图")

        final_reports = []

        for scenario in scenarios:
            victim_ip = scenario['victim_ip']
            events = scenario['events']  # 按时间排序的 AttackEvent 列表

            if not events:
                continue

            # 2. 路径回溯与证据增强
            # 针对该场景中的第一个事件（入口）进行深入回溯
            root_event_id = events[0]['id']
            root_event_time = events[0]['timestamp']  # 获取开始时间用于时序分析

            # [修改点] 传入时间参数，并在内部调用复杂的入侵检测逻辑
            trace_context = self._trace_root_cause_and_infrastructure(
                root_event_id,
                victim_ip,
                events,
                root_event_time
            )

            # 3. 攻击表示学习 (Attack Representation)
            attack_signature = self._vectorize_scenario(events, trace_context)

            # 4. 相似度匹配 (Similarity Matching)
            match_result = self._match_known_apts(attack_signature['ttp_set'])

            # 5. 结果处理与闭环
            if match_result['is_match']:
                logging.info(f"场景 {scenario['scenario_id']} 匹配到已知组织: {match_result['best_match']}")
                profile_type = "Known APT"
            else:
                logging.info(f"场景 {scenario['scenario_id']} 未匹配已知组织，生成新画像")
                profile_type = "Unknown Actor"
                self._save_new_attacker_profile(attack_signature, trace_context)

            # 6. 生成综合报告
            report = {
                "scenario_id": scenario['scenario_id'],
                "victim_ip": victim_ip,
                "time_window": f"{events[0]['timestamp']} to {events[-1]['timestamp']}",
                "attribution": {
                    "type": profile_type,
                    "result": match_result
                },
                "attack_chain": [e['technique_name'] for e in events],
                "infrastructure": trace_context['infrastructure'],
                "root_cause_analysis": trace_context['root_cause']  # 详细的入侵分析结果
            }
            final_reports.append(report)

        return final_reports

    def _extract_attack_scenarios(self):
        """
        利用 NEXT_STAGE 关系提取完整的攻击链子图
        """
        query = """
        MATCH (start:AttackEvent)
        WHERE NOT ()-[:NEXT_STAGE]->(start)

        MATCH path = (start)-[:NEXT_STAGE*0..10]->(end:AttackEvent)

        WITH start, collect(DISTINCT end) AS chain_nodes
        WHERE size(chain_nodes) >= 2 

        UNWIND chain_nodes AS evt
        MATCH (evt)-[:IS_TYPE]->(t:Technique)

        RETURN 
            start.victim_ip AS victim_ip,
            start.timestamp_start AS start_time,  // [修改点1] 将时间加入返回列表，作为分组键之一
            collect({
                id: evt.id, 
                timestamp: evt.timestamp_start, 
                technique_id: t.id, 
                technique_name: t.name,
                stage: evt.stage_order
            }) AS events
        ORDER BY start_time DESC  // [修改点2] 使用返回列表中的别名进行排序
        """
        with self.driver.session() as session:
            result = session.run(query)
            scenarios = []
            for record in result:
                sorted_events = sorted(record['events'], key=lambda x: x['timestamp'])
                scenarios.append({
                    "scenario_id": str(uuid.uuid4()),
                    "victim_ip": record['victim_ip'],
                    "events": sorted_events
                })
            return scenarios

    def _trace_root_cause_and_infrastructure(self, root_event_id, victim_ip, all_events, root_timestamp):
        """
        [修改版] 在所有相关事件中寻找最早的进程链作为根因，而不仅限于第一个事件
        """
        event_ids = [e['id'] for e in all_events]

        # 1. 基础设施提取 (保持不变)
        infra_query = """
        UNWIND $eids AS eid
        MATCH (ae:AttackEvent {id: eid})
        MATCH (entity)-[:TRIGGERED]->(ae)
        OPTIONAL MATCH (entity)-[:Resolve]->(d:Domain)
        OPTIONAL MATCH (entity)-[:Connect]->(ip:IP) WHERE ip.type = 'External'
        OPTIONAL MATCH (entity)-[:Write]->(f:File)
        RETURN 
            collect(DISTINCT d.name) AS domains,
            collect(DISTINCT ip.ip) AS ips,
            collect(DISTINCT f.hash) AS file_hashes,
            collect(DISTINCT entity.hash) AS proc_hashes
        """

        # 2. [核心修改] 遍历所有事件，寻找最早的 Process 实体，并向上回溯
        # 不再依赖 $root_id，而是使用 UNWIND $eids
        root_trace_query = """
        UNWIND $eids AS eid
        MATCH (ae:AttackEvent {id: eid})<-[:TRIGGERED]-(entity:Process)

        // 向上找父进程链，直到找不到父进程
        MATCH path = (root:Process)-[:Spawn*0..5]->(entity)
        WHERE NOT (root)<-[:Spawn]-()

        // 返回结果，并按关联事件的时间排序，取最早的一个
        RETURN root.name AS root_name, root.pid AS root_pid, root.user AS user, ae.timestamp_start AS ts
        ORDER BY ts ASC
        LIMIT 1
        """

        context = {
            "root_cause": {},
            "infrastructure": {}
        }

        with self.driver.session() as session:
            # 执行基础设施查询
            infra_res = session.run(infra_query, eids=event_ids).single()
            if infra_res:
                context['infrastructure'] = {
                    "domains": [d for d in infra_res['domains'] if d],
                    "ips": [i for i in infra_res['ips'] if i],
                    "hashes": [h for h in infra_res['proc_hashes'] if h] + [h for h in infra_res['file_hashes'] if h]
                }
                # 情报富化 (保持不变)
                if context['infrastructure']['domains']:
                    try:
                        domain_info = self.ti_engine.get_domain_report(context['infrastructure']['domains'][0])
                        if domain_info:
                            context['infrastructure']['vt_info'] = domain_info
                    except Exception:
                        pass

            # [修改] 传入 eids 列表而不是 root_id
            root_res = session.run(root_trace_query, eids=event_ids).single()

            if root_res:
                root_name = root_res['root_name']
                root_pid = root_res['root_pid']
                # 使用该进程对应事件的时间，或者传入的整个场景开始时间
                incident_time = root_res['ts'] or root_timestamp

                logging.info(f"定位到根进程: {root_name} (PID: {root_pid})，开始深度研判...")

                detailed_cause = self._identify_initial_intrusion(
                    victim_ip,
                    root_name,
                    root_pid,
                    incident_time
                )
                context['root_cause'] = detailed_cause
            else:
                context['root_cause'] = {
                    "type": "Unknown",
                    "evidence": "No process chain found (Network-only or Credential-based event?)"
                }

        return context

    def _identify_initial_intrusion(self, victim_ip, root_proc_name, root_proc_pid, attack_time):
        """
        [移植自 Attack_Provenance.py]
        识别初始入侵点：基于“流量-服务-进程”强绑定与“边界日志”推断
        """
        # 构造 Cypher 查询
        query = """
        // =========================================================
        // 场景 1: 面向公网应用的漏洞利用 (高置信度)
        // 逻辑：外部IP -> 流量(端口匹配) -> Web进程 -> 衍生恶意进程
        // =========================================================
        MATCH (root:Process {host: $ip, pid: $pid})
        // 确保 root 进程在攻击开始前或同时存在
        WHERE datetime(root.timestamp) <= datetime($ts)

        // 查找在该进程启动前，外部IP对该主机的入站流量
        MATCH (attacker:IP)-[flow:Traffic_Flow]->(victim:IP {id: $ip})
        WHERE attacker.type = 'External'  
          AND datetime(flow.timestamp) >= datetime(root.timestamp) - duration('PT10M') 
          AND datetime(flow.timestamp) <= datetime(root.timestamp)

        // 强关联：进程名暗示了它是一个网络服务
        AND (
            root.name =~ '(?i).*(java|w3wp|tomcat|nginx|httpd|php|node).*'
            OR
            exists((root)-[:LISTEN]->()) 
        )

        RETURN 
            'Exploit Public-Facing Application' AS type,
            attacker.ip AS intruder_ip,
            'High' AS confidence,
            'Attacker accessed port ' + toString(flow.dst_port) + ' of service ' + root.name AS evidence,
            flow.timestamp AS entry_time

        UNION ALL

        // =========================================================
        // 场景 2: 远程服务/有效账号利用 (VPN, SSH, RDP)
        // 逻辑：外部IP -> 登录事件(Logon) -> 同一用户启动进程
        // =========================================================
        MATCH (root:Process {host: $ip, pid: $pid})
        WHERE datetime(root.timestamp) <= datetime($ts)

        MATCH (attacker:IP)-[ls:Logon_Source]->(victim:IP {id: $ip})
        WHERE attacker.type = 'External'
          AND datetime(ls.timestamp) >= datetime(root.timestamp) - duration('PT2H') 
          AND datetime(ls.timestamp) <= datetime(root.timestamp)

        MATCH (u:User)-[l:Logon]->(victim)
        WHERE u.username = root.user 
          AND abs(duration.inSeconds(datetime(l.timestamp), datetime(ls.timestamp)).seconds) < 60

        RETURN 
            'Valid Accounts / Remote Service' AS type,
            attacker.ip AS intruder_ip,
            'Medium' AS confidence,
            'User ' + u.username + ' logged in from external source' AS evidence,
            ls.timestamp AS entry_time

        UNION ALL

        // =========================================================
        // 场景 3: 钓鱼/用户执行 (Phishing)
        // 逻辑：浏览器/邮件 -> 下载文件 -> 文件被执行(即 Root Process)
        // =========================================================
        MATCH (root:Process {host: $ip, pid: $pid})

        MATCH (browser:Process)-[w:Write]->(f:File)
        WHERE (f.name = root.name OR root.cmdline CONTAINS f.name)
          AND browser.name =~ '(?i).*(chrome|firefox|edge|outlook|foxmail).*'
          AND datetime(w.timestamp) <= datetime(root.timestamp)

        RETURN 
            'Phishing / User Execution' AS type,
            'Unknown (File from Web)' AS intruder_ip,
            'Medium' AS confidence,
            'Malicious file downloaded by ' + browser.name AS evidence,
            w.timestamp AS entry_time
        """

        with self.driver.session() as session:
            try:
                result = session.run(query, ip=victim_ip, pid=root_proc_pid, ts=attack_time)
                record = result.single()
                if record:
                    return record.data()
            except Exception as e:
                logging.warning(f"入侵点研判查询失败: {e}")

            # 默认返回
            return {
                "type": "Unknown / Lateral Movement",
                "intruder_ip": "Internal or Unknown",
                "confidence": "Low",
                "evidence": "No direct external boundary logs correlated",
                "root_process": f"{root_proc_name} ({root_proc_pid})"
            }

    def _vectorize_scenario(self, events, trace_context):
        """
        [算法核心] 将攻击场景转化为特征向量
        """
        ttp_set = set([e['technique_id'] for e in events])
        infra = trace_context['infrastructure']

        fingerprint = {
            "ttp_count": len(ttp_set),
            "domains": sorted(infra.get('domains', [])),
            "ips": sorted(infra.get('ips', []))
        }

        return {
            "ttp_set": ttp_set,
            "fingerprint": fingerprint
        }

    def _match_known_apts(self, detected_ttps):
        """
        [相似度计算] 计算 Jaccard 系数匹配已知 APT 组织
        """
        query = """
        MATCH (is:IntrusionSet)-[:USES]->(t:Technique)
        RETURN is.id AS group_name, collect(t.id) AS group_ttps
        """

        best_match = None
        max_score = 0.0
        details = []

        with self.driver.session() as session:
            results = session.run(query)

            for record in results:
                group_name = record['group_name']
                group_ttps = set(record['group_ttps'])

                intersection = len(detected_ttps.intersection(group_ttps))
                union = len(detected_ttps.union(group_ttps))

                if union == 0: continue
                score = intersection / union

                if score > 0.1:
                    details.append({
                        "group": group_name,
                        "score": round(score, 3),
                        "overlap": list(detected_ttps.intersection(group_ttps))
                    })

                if score > max_score:
                    max_score = score
                    best_match = group_name

        is_match = max_score > 0.2

        return {
            "is_match": is_match,
            "best_match": best_match,
            "confidence_score": max_score,
            "candidates": sorted(details, key=lambda x: x['score'], reverse=True)[:3]
        }

    def _save_new_attacker_profile(self, signature, context):
        """
        [画像生成] 将未知的攻击模式存入数据库
        """
        profile_id = str(uuid.uuid4())[:8]
        ttps = list(signature['ttp_set'])
        domains = context['infrastructure'].get('domains', [])

        query = """
        MERGE (ap:AttackerProfile {ttps_hash: $ttps_hash})
        ON CREATE SET 
            ap.id = $pid,
            ap.first_seen = datetime(),
            ap.ttps = $ttps,
            ap.domains = $domains
        ON MATCH SET
            ap.last_seen = datetime(),
            ap.sightings = coalesce(ap.sightings, 0) + 1

        WITH ap
        UNWIND $ttps AS t_id
        MATCH (t:Technique {id: t_id})
        MERGE (ap)-[:USES]->(t)
        """

        ttps_hash = hash(tuple(sorted(ttps)))

        with self.driver.session() as session:
            session.run(query,
                        pid=profile_id,
                        ttps_hash=ttps_hash,
                        ttps=ttps,
                        domains=domains)
            logging.info(f"已保存新的攻击者画像: {profile_id}")


if __name__ == "__main__":
    engine = APTAnalysisEngine("bolt://localhost:7687", "neo4j", "00000000")
    try:
        report = engine.run_pipeline()
        print(json.dumps(report, indent=4, ensure_ascii=False))
    except Exception as e:
        print(f"Error: {e}")
    finally:
        engine.close()