import logging
from neo4j import GraphDatabase
import json
from utils.trace.Threat_Intel import  VirusTotalEnricher
import os
# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class AttackProvenanceAnalyzer:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        vt_key = os.getenv("VT_API_KEY", "ccccce76f24f200b35412471d447776e6cafd120c42cc2a44dc2ebd33f098532")
        self.ti_engine = VirusTotalEnricher(vt_key)

    def close(self):
        self.driver.close()

    def run_full_analysis(self):
        """
        执行完整的溯源分析流程
        """
        print("=" * 50)
        print("开始攻击溯源分析...")
        print("=" * 50)

        # 1. 识别高危攻击事件簇 (获取所有 AttackEvent)
        attack_events = self._get_high_confidence_events()
        logging.info(f"发现 {len(attack_events)} 个高置信度攻击事件，开始逐个回溯...")

        report = []

        for evt in attack_events:
            event_id = evt['id']
            technique = evt['technique']

            analysis_result = {
                "alert_id": event_id,
                "trigger_technique": technique,
                "victim_ip": evt['victim_ip'],
                "paths": {},
                "attacker_profile": {}
            }

            # 2. 攻击路径重建
            # 2.1 寻找进程树根源 (Root Cause)
            analysis_result["paths"]["process_tree"] = self._trace_process_root(event_id)

            # 2.2 寻找横向移动来源 (Lateral Movement Source)
            analysis_result["paths"]["lateral_source"] = self._trace_lateral_movement(evt['victim_ip'],
                                                                                      evt['timestamp_start'])

            # 2.3 寻找数据外传路径 (Data Exfiltration)
            analysis_result["paths"]["exfiltration"] = self._detect_exfiltration(evt['victim_ip'])

            # [新增] 4. 因果关系推断 (弥补日志缺失导致的断链)
            # 查找该攻击时间点前后，是否存在隐式的 "文件释放 -> 进程执行" 关系
            implicit_links = self.infer_implicit_causality(
                evt['victim_ip'],
                evt['timestamp_start'],
                None  # 需要调整函数参数接收时间窗口
            )
            if implicit_links:
                analysis_result["paths"]["inferred_causality"] = implicit_links
                logging.info(f"推断出 {len(implicit_links)} 条隐式因果关系")

            # 3. 攻击者身份画像
            # 3.1 提取指纹 (Hash, Domain, C2)
            analysis_result["attacker_profile"] = self._extract_fingerprints(event_id)

            # 3.2 组织匹配 (简单的 TTP 匹配模拟)
            analysis_result["attacker_profile"]["suspected_apt"] = self._match_apt_group(
                analysis_result["attacker_profile"]["techniques"])

            report.append(analysis_result)

        return report

    def _get_high_confidence_events(self):
        """
        获取所有置信度为 High 的攻击告警
        """
        query = """
        MATCH (ae:AttackEvent)-[:IS_TYPE]->(t:Technique)
        WHERE ae.confidence = 'High'
        RETURN ae.id AS id, ae.victim_ip AS victim_ip, ae.timestamp_start AS timestamp_start, t.name AS technique
        ORDER BY ae.timestamp_start DESC
        """
        with self.driver.session() as session:
            result = session.run(query)
            return [record.data() for record in result]

    def _trace_process_root(self, attack_event_id):
        """
        [路径重建] 从告警点向上回溯进程树，找到可能的入口进程
        逻辑：AttackEvent <- Triggered - Process <- Spawn* - Process (Root)
        """
        query = """
        MATCH (ae:AttackEvent {id: $ae_id})<-[:TRIGGERED]-(entity)
        WHERE 'Process' IN labels(entity)
        // 向上递归查找父进程，最大深度10层
        MATCH path = (root:Process)-[:Spawn*0..10]->(entity)
        WHERE NOT (root)<-[:Spawn]-() // 找到没有父进程的节点（当前视野内的根）
        RETURN 
            root.name AS root_process, 
            root.pid AS root_pid, 
            root.cmdline AS root_cmd,
            root.user AS user,
            [n in nodes(path) | n.name] AS execution_chain
        """
        with self.driver.session() as session:
            result = session.run(query, ae_id=attack_event_id)
            data = result.single()
            if data:
                return data.data()
            return "No process chain found (Event might be network-only)"

    def _trace_lateral_movement(self, victim_ip, timestamp):
        """
        [路径重建] 查找在攻击发生前，是否有来自其他 IP 的登录或连接
        逻辑：Victim_IP <-[Logon]- User -[Logon_Source]- Source_IP
        """
        query = """
                MATCH (victim:IP {id: $ip})<-[l:Logon]-(u:User)
                MATCH (src:IP)-[ls:Logon_Source]->(victim)
                WHERE ls.user = u.username
                  AND datetime(ls.timestamp) <= datetime($ts) 
                  AND datetime(ls.timestamp) >= datetime($ts) - duration('PT1H')
                RETURN src.ip AS source_ip, u.username AS compromised_user, ls.timestamp AS logon_time
                """
        with self.driver.session() as session:
            result = session.run(query, ip=victim_ip, ts=timestamp)
            return [record.data() for record in result]

    def _detect_exfiltration(self, host_ip):
        """
        [路径重建] 检测敏感文件读取后紧接着的外联行为
        逻辑：File <-[Read]- Process -[Connect]-> External_IP
        """
        query = """
                MATCH (host:IP {id: $ip})
                MATCH (f:File)<-[:Read]-(p:Process)-[:Connect]->(dest_ip:IP)
                WHERE p.host = $ip AND dest_ip.ip <> $ip
                AND NOT dest_ip.ip STARTS WITH '192.168.' 
                AND NOT dest_ip.ip STARTS WITH '10.'
                RETURN f.path AS sensitive_file, p.name AS leaking_process, dest_ip.ip AS destination_ip
                """
        with self.driver.session() as session:
            result = session.run(query, ip=host_ip)
            return [record.data() for record in result]

    def _extract_fingerprints(self, attack_event_id):
        """
        [身份溯源] 提取攻击相关的所有实体指纹 (Hash, Domain, User Agent等) 并进行情报富化
        """
        query = """
        MATCH (ae:AttackEvent {id: $ae_id})
        // 1. 获取触发告警的实体周边环境
        MATCH (ae)<-[:TRIGGERED]-(entity)

        // 2. 如果是进程，找它的 Hash 和它释放的文件 Hash
        OPTIONAL MATCH (entity)-[:Write]->(dropped_file:File)
        WHERE 'Process' IN labels(entity)

        // 3. 如果有网络连接，找域名
        OPTIONAL MATCH (entity)-[:Resolve]->(domain:Domain)

        // 4. 汇总同一主机上该时间段的所有相关技术
        OPTIONAL MATCH (entity)-[:Spawn*0..5]-(related_proc:Process)-[:TRIGGERED]->(other_ae:AttackEvent)-[:IS_TYPE]->(tech:Technique)

        RETURN 
            collect(DISTINCT entity.hash) + collect(DISTINCT dropped_file.hash) AS hashes,
            collect(DISTINCT domain.name) AS c2_domains,
            collect(DISTINCT tech.name) AS techniques
        """

        with self.driver.session() as session:
            result = session.run(query, ae_id=attack_event_id)
            record = result.single()

            if record:
                # 清洗数据，去除 None
                hashes = [h for h in record['hashes'] if h]
                domains = [d for d in record['c2_domains'] if d]
                techniques = [t for t in record['techniques'] if t]

                # 【修正点 1】必须先初始化列表，否则后面 append 会报错 NameError
                enriched_infrastructure = []

                if domains:
                    print(f"正在对 {len(domains)} 个域名进行外部情报查询...")

                    for domain in domains:
                        # 过滤掉内部域名或空白 (增加 localhost 过滤)
                        if not domain or domain.endswith(".local") or domain == "localhost":
                            continue

                        # 【修正点 2】确保 __init__ 中已经初始化了 self.ti_engine
                        # 如果没有初始化，这里会报 AttributeError
                        try:
                            ti_data = self.ti_engine.get_domain_report(domain)

                            if ti_data:
                                enriched_infrastructure.append(ti_data)

                                # 如果发现高危域名 (>2家引擎报毒)，标记为 C2
                                # 注意：要确保 Threat_Intel.py 返回的数据结构里包含 reputation_score
                                if ti_data.get('reputation_score', 0) > 2:
                                    logging.warning(f"发现确认为恶意的 C2 域名: {domain}")
                        except Exception as e:
                            logging.error(f"情报查询出错 ({domain}): {e}")

                return {
                    "malware_hashes": list(set(hashes)),
                    "c2_domains": list(set(domains)),
                    "techniques": list(set(techniques)),
                    # [新增] 详细的情报数据，用于生成报告
                    "infrastructure_intelligence": enriched_infrastructure
                }

            return {}

    # 修改 Attack_Provenance.py -> _match_apt_group

    def _match_apt_group(self, detected_techniques):
        """
        使用 Jaccard 相似度进行 APT 组织匹配
        """
        # 扩充知识库，包含 ID
        apt_db = {
            "APT28": {"T1110", "T1059.001", "T1048", "T1132"},
            "Lazarus": {"T1059.001", "T1078", "T1204", "T1083"}
            # ... 更多数据
        }

        detected_set = set(detected_techniques)  # 假设输入已经是 ["T1110", "T1059"] 格式
        matches = []

        for group, ttp_set in apt_db.items():
            # 计算交集
            intersection = detected_set.intersection(ttp_set)
            # 计算并集
            union = detected_set.union(ttp_set)

            if not union: continue

            # Jaccard Score = 交集 / 并集
            score = len(intersection) / len(union)

            # 只有相似度超过一定阈值 (如 0.2) 或命中关键技术才报告
            if score > 0.1 or len(intersection) >= 2:
                matches.append({
                    "group": group,
                    "similarity_score": round(score, 2),
                    "matched_techniques": list(intersection),
                    "missing_techniques": list(ttp_set - detected_set)  # 提示还缺什么证据
                })

        # 按相似度降序排列
        return sorted(matches, key=lambda x: x['similarity_score'], reverse=True)

    def infer_implicit_causality(self, victim_ip, start_time, end_time):
        """
        推断因果关系：当显式进程链断裂时，基于[同一主机 + 极短时间差]推断关联
        场景例：文件释放(File Write) -> 1秒后 -> 进程创建(Process Create)
        """
        query = """
        MATCH (f:File)<-[w:Write]-(p1:Process)
        MATCH (p2:Process)-[s:Spawn]->()
        WHERE p1.host = $ip AND p2.host = $ip
          // p1 写文件的时间，略早于 p2 启动的时间 (比如 5秒内)
          AND datetime(w.timestamp) <= datetime(p2.timestamp)
          AND duration.inSeconds(datetime(w.timestamp), datetime(p2.timestamp)).seconds < 5
          // 且 p2 执行的文件路径与 p1 写入的路径相似或相同
          AND (p2.cmdline CONTAINS f.name OR p2.name = f.name)

        RETURN p1.name AS dropper, f.name AS payload, p2.name AS execution, 
               duration.inSeconds(datetime(w.timestamp), datetime(p2.timestamp)).seconds AS lag
        """
        with self.driver.session() as session:
            return [record.data() for record in session.run(query, ip=victim_ip)]

# ==========================================
# 测试运行
# ==========================================
if __name__ == "__main__":
    # 请确保 Neo4j 数据库已运行且已有 Graph_construct.py 导入的数据
    analyzer = AttackProvenanceAnalyzer("bolt://localhost:7687", "neo4j", "00000000")

    try:
        results = analyzer.run_full_analysis()
        print(json.dumps(results, indent=4, ensure_ascii=False))

        # 将结果保存为报告
        with open("attack_provenance_report.json", "w", encoding='utf-8') as f:
            json.dump(results, f, indent=4, ensure_ascii=False)
            print("\n报告已生成: attack_provenance_report.json")

    except Exception as e:
        logging.error(f"分析过程中出错: {e}")
    finally:
        analyzer.close()