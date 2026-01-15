import logging
from neo4j import GraphDatabase

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class GraphIngestionEngine:
    def __init__(self, uri, user, password, initial_pid_cache=None):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        self.pid_cache = initial_pid_cache if initial_pid_cache else {}

    def get_current_pid_cache(self):
        return self.pid_cache

    def close(self):
        self.driver.close()

    # =========================================================================
    # [优化 1] 通用分批写入工具
    # =========================================================================
    def _batch_execute(self, query, data_list, batch_size=1000, param_name="events", **kwargs):
        """
        :param query: Cypher 语句
        :param data_list: 数据列表
        :param batch_size: 单次事务提交的条数
        :param param_name: Cypher 中 UNWIND 后面的参数名
        """
        if not data_list:
            return

        total = len(data_list)
        with self.driver.session() as session:
            for i in range(0, total, batch_size):
                batch = data_list[i: i + batch_size]
                try:
                    params = {param_name: batch}
                    params.update(kwargs)
                    session.execute_write(lambda tx: tx.run(query, **params))
                except Exception as e:
                    logging.error(f"批量写入失败 (Range {i}-{i + len(batch)}): {e}")

    # =========================================================================
    # [优化 2] 大规模更新查询工具 (auto-commit)
    # =========================================================================
    def _run_massive_update(self, query, **kwargs):
        """
        运行包含 CALL { ... } IN TRANSACTIONS 的大查询
        """
        try:
            with self.driver.session() as session:
                session.run(query, **kwargs)
        except Exception as e:
            logging.error(f"大规模更新任务失败: {e}")

    def _generate_process_id(self, host_ip, pid, timestamp=None):
        key = f"{host_ip}_{pid}"
        if timestamp and timestamp != "unknown":
            self.pid_cache[key] = timestamp
            time_suffix = timestamp
        else:
            time_suffix = self.pid_cache.get(key, "unknown")
        return f"{host_ip}_{pid}_{time_suffix}"

    def ingest_host_behavior(self, data_list):
        if not data_list:
            return

        # 预处理：建立 PID 缓存
        for item in data_list:
            if item.get("event_type") == "process_create":
                entities = item.get("entities", {})
                self._generate_process_id(item.get("host_ip"), entities.get("pid"), item.get("timestamp"))

        # 预处理数据
        processed_data = []
        for item in data_list:
            entities = item.get("entities", {})
            features = item.get("behavior_features", {})
            ts_for_id = item.get("timestamp") if item.get("event_type") == "process_create" else None
            proc_id = self._generate_process_id(item.get("host_ip"), entities.get("pid"), ts_for_id)

            processed_data.append({
                "host_ip": item.get("host_ip"),
                "timestamp": item.get("timestamp"),
                "event_type": item.get("event_type"),
                "entities": entities,
                "features": features,
                "pid": entities.get("pid"),
                "proc_name": entities.get("process_name"),
                "proc_hash": entities.get("hash"),
                "proc_id": proc_id,
                "parent_id": f"{item.get('host_ip')}_{entities.get('parent_pid')}_unknown" if item.get(
                    "event_type") == "process_create" else None
            })

        # 1. 进程创建
        spawn_query = """
        UNWIND $events AS event
        WITH event WHERE event.event_type = 'process_create' AND event.pid IS NOT NULL
        MERGE (p:Process {id: event.parent_id})
        ON CREATE SET p.name = event.entities.parent_process
        MERGE (c:Process {id: event.proc_id})
        ON CREATE SET 
            c.name = event.proc_name, c.pid = event.pid, c.cmdline = event.entities.command_line,
            c.host = event.host_ip, c.timestamp = event.timestamp, c.hash = event.proc_hash, 
            c.ports = event.entities.listen_ports
        MERGE (p)-[r:Spawn]->(c)
        SET r.timestamp = event.timestamp, r.is_abnormal = event.features.is_abnormal_parent
        """
        spawn_data = [d for d in processed_data if d["event_type"] == "process_create"]
        self._batch_execute(spawn_query, spawn_data, param_name="events")

        # 2. 文件操作
        file_ops_map = {
            "file_create": "Write", "file_modify": "Write",
            "file_delete": "Delete", "file_read": "Read", "image_load": "Load"
        }
        for evt_type, relation in file_ops_map.items():
            file_query = f"""
            UNWIND $events AS event
            WITH event 
            MERGE (p:Process {{id: event.proc_id}})
            MERGE (f:File {{id: event.host_ip + '_' + event.entities.file_path}})
            ON CREATE SET 
                f.path = event.entities.file_path, f.name = event.entities.file_name,
                f.host = event.host_ip, f.hash = event.entities.hash
            MERGE (p)-[r:{relation}]->(f)
            SET r.timestamp = event.timestamp
            """
            batch_data = [d for d in processed_data if d["event_type"] == evt_type and d["entities"].get("file_path")]
            self._batch_execute(file_query, batch_data, param_name="events")

        # 3. 注册表操作
        reg_query = """
        UNWIND $events AS event
        WITH event
        MERGE (p:Process {id: event.proc_id})
        MERGE (r:Registry {id: event.entities.registry_key})
        ON CREATE SET 
            r.key = event.entities.registry_key, r.value_name = event.entities.registry_value_name,
            r.value_data = event.entities.registry_value_data
        MERGE (p)-[rel:Write]->(r)
        SET rel.timestamp = event.timestamp
        """
        reg_data = [d for d in processed_data if d["event_type"] == "registry_set_value"]
        self._batch_execute(reg_query, reg_data, param_name="events")

        # 4. 网络连接
        net_conn_query = """
        UNWIND $events AS event
        WITH event
        MERGE (p:Process {id: event.proc_id})
        MERGE (ip:IP {id: event.entities.dst_ip})
        ON CREATE SET ip.ip = event.entities.dst_ip
        MERGE (p)-[r:Connect]->(ip)
        SET r.timestamp = event.timestamp, r.dst_port = event.entities.dst_port
        """
        net_data = [d for d in processed_data if
                    d["event_type"] == "network_connection" and d["entities"].get("dst_ip")]
        self._batch_execute(net_conn_query, net_data, param_name="events")

        # 5. 进程注入
        inject_query = """
        UNWIND $events AS event
        WITH event
        MERGE (src:Process {id: event.proc_id})
        MERGE (target:Process {id: event.target_proc_id})
        MERGE (src)-[r:Inject]->(target)
        SET r.timestamp = event.timestamp, r.is_memory_injection = true
        """
        inject_data = []
        for d in processed_data:
            if d["event_type"] == "process_injection" and d["entities"].get("target_pid"):
                d["target_proc_id"] = self._generate_process_id(d["host_ip"], d["entities"].get("target_pid"),
                                                                "unknown")
                inject_data.append(d)
        self._batch_execute(inject_query, inject_data, param_name="events")

        logging.info(f"已分批处理 {len(processed_data)} 条主机行为数据")

    def ingest_network_traffic(self, data_list):
        if not data_list:
            return

        processed_data = []
        for item in data_list:
            processed_data.append({
                "src_ip": item.get("src_ip"), "dst_ip": item.get("dst_ip"),
                "src_port": item.get("src_port"), "dst_port": item.get("dst_port"),
                "timestamp": item.get("timestamp"), "event_type": item.get("event_type"),
                "domain": item.get("entities", {}).get("domain"),
                "protocol": item.get("protocol"),
                "features": item.get("traffic_features", {})
            })

        # 1. 流量
        flow_query = """
        UNWIND $events AS event
        WITH event WHERE event.src_ip IS NOT NULL AND event.dst_ip IS NOT NULL
        MERGE (src:IP {id: event.src_ip}) 
        ON CREATE SET src.ip = event.src_ip, src.type = CASE WHEN event.src_ip STARTS WITH '192.168.' OR event.src_ip STARTS WITH '10.' THEN 'Internal' ELSE 'External' END
        MERGE (dst:IP {id: event.dst_ip}) 
        ON CREATE SET dst.ip = event.dst_ip, dst.type = CASE WHEN event.dst_ip STARTS WITH '192.168.' OR event.dst_ip STARTS WITH '10.' THEN 'Internal' ELSE 'External' END
        MERGE (src)-[r:Traffic_Flow]->(dst)
        SET r.timestamp = event.timestamp, r.protocol = event.protocol,
            r.src_port = event.src_port, r.dst_port = event.dst_port,
            r.event_type = event.event_type
        """
        self._batch_execute(flow_query, processed_data, param_name="events")

        # 2. DNS
        dns_query = """
        UNWIND $events AS event
        WITH event WHERE event.domain IS NOT NULL
        MERGE (src:IP {id: event.src_ip})
        MERGE (d:Domain {id: event.domain}) ON CREATE SET d.name = event.domain
        MERGE (src)-[r:Resolve]->(d)
        SET r.timestamp = event.timestamp, r.query_type = event.features.query_type,
            r.is_suspicious = event.features.is_covert_channel
        """
        self._batch_execute(dns_query, processed_data, param_name="events")
        logging.info(f"已分批处理 {len(processed_data)} 条流量数据")

    def ingest_host_log(self, data_list):
        if not data_list:
            return

        processed_data = []
        for item in data_list:
            if item.get("event_type") == "user_logon":
                processed_data.append({
                    "host_ip": item.get("host_ip"), "timestamp": item.get("timestamp"),
                    "user": item.get("entities", {}).get("user"),
                    "src_ip": item.get("entities", {}).get("src_ip")
                })

        logon_query = """
        UNWIND $events AS event
        WITH event WHERE event.user IS NOT NULL
        MERGE (u:User {id: event.host_ip + '_' + event.user}) ON CREATE SET u.username = event.user
        MERGE (host:IP {id: event.host_ip}) ON CREATE SET host.ip = event.host_ip
        MERGE (u)-[r:Logon]->(host) SET r.timestamp = event.timestamp
        FOREACH (ignoreMe IN CASE WHEN event.src_ip IS NOT NULL THEN [1] ELSE [] END |
            MERGE (src:IP {id: event.src_ip}) ON CREATE SET src.ip = event.src_ip
            MERGE (src)-[rel:Logon_Source]->(host)
            SET rel.timestamp = event.timestamp, rel.user = event.user
        )
        """
        self._batch_execute(logon_query, processed_data, param_name="events")

    def ingest_attack_events(self, attack_data_list):
        if not attack_data_list:
            return

        # 1. 基础关联入库
        ingest_query = """
        UNWIND $batch AS data
        MERGE (t:Technique {id: data.technique.id})
        ON CREATE SET t.name = data.technique.name, t.tactic_id = data.tactic.id, t.tactic_name = data.tactic.name
        MERGE (ae:AttackEvent {id: data.attack_id})
        ON CREATE SET 
            ae.confidence = data.confidence, ae.timestamp_start = data.timestamp_start,
            ae.timestamp_end = data.timestamp_end, ae.stage_order = data.stage_order,
            ae.victim_ip = data.victim_ip
        MERGE (ae)-[:IS_TYPE]->(t)

        WITH ae, data.related_events AS evidence_ids
        UNWIND evidence_ids AS eid
        OPTIONAL MATCH (exact_p:Process {id: eid})
        FOREACH (_ IN CASE WHEN exact_p IS NOT NULL THEN [1] ELSE [] END | MERGE (exact_p)-[:TRIGGERED]->(ae))

        WITH ae, eid
        OPTIONAL MATCH (fuzzy_p:Process)
        WHERE eid ENDS WITH 'unknown' AND fuzzy_p.id STARTS WITH split(eid, '_unknown')[0] 
        FOREACH (_ IN CASE WHEN fuzzy_p IS NOT NULL THEN [1] ELSE [] END | MERGE (fuzzy_p)-[:TRIGGERED]->(ae))

        WITH ae, eid
        OPTIONAL MATCH (d:Domain {id: eid})
        FOREACH (_ IN CASE WHEN d IS NOT NULL THEN [1] ELSE [] END | MERGE (d)-[:TRIGGERED]->(ae))
        WITH ae, eid
        OPTIONAL MATCH (f:File {id: eid})
        FOREACH (_ IN CASE WHEN f IS NOT NULL THEN [1] ELSE [] END | MERGE (f)-[:TRIGGERED]->(ae))
        WITH ae, eid
        OPTIONAL MATCH (r:Registry {id: eid})
        FOREACH (_ IN CASE WHEN r IS NOT NULL THEN [1] ELSE [] END | MERGE (r)-[:TRIGGERED]->(ae))
        WITH ae, eid
        OPTIONAL MATCH (i:IP {id: eid})
        FOREACH (_ IN CASE WHEN i IS NOT NULL THEN [1] ELSE [] END | MERGE (i)-[:TRIGGERED]->(ae))
        """
        self._batch_execute(ingest_query, attack_data_list, param_name="batch")

        # 2. [关键修复] 构建时序链 (NEXT_STAGE)
        # 修复逻辑：增加 ID 比较以打破时间相同导致的死循环
        chain_query = """
                MATCH (a1:AttackEvent), (a2:AttackEvent)
                WHERE a1.victim_ip = a2.victim_ip
                  AND a1.id <> a2.id
                  AND datetime(a1.timestamp_start) > datetime() - duration('P1D') 
                  AND datetime(a2.timestamp_start) > datetime() - duration('P1D')

                  // FIX: 防止毫秒级并发导致的双向连接（死循环）
                  AND (
                      datetime(a1.timestamp_end) < datetime(a2.timestamp_start)
                      OR 
                      (datetime(a1.timestamp_end) = datetime(a2.timestamp_start) AND a1.id < a2.id)
                  )

                  AND duration.inSeconds(datetime(a1.timestamp_end), datetime(a2.timestamp_start)).seconds < $window
                  AND NOT (a1)-[:NEXT_STAGE]->(a2)

                CALL (a1, a2) {
                    MERGE (a1)-[r:NEXT_STAGE]->(a2)
                    SET r.type = 'temporal', r.confidence = 'Low'
                } IN TRANSACTIONS OF 100 ROWS
                """
        self._run_massive_update(chain_query, window=600)
        logging.info(f"已分批处理 {len(attack_data_list)} 条 ATT&CK 事件并更新时序链")

    def build_causal_chains(self, time_window_seconds=7200, max_hops=10):
        logging.info("开始执行因果关联分析...")

        # [优化修复] 降低最短路径深度，减小 Batch Size，防止死循环
        causal_query = """
        MATCH (a1:AttackEvent)
        MATCH (a2:AttackEvent)
        WHERE a1.victim_ip = a2.victim_ip
          AND a1.attack_id <> a2.attack_id
          AND datetime(a1.timestamp_start) > datetime() - duration('P1D')
          AND datetime(a2.timestamp_start) > datetime() - duration('P1D')

          // FIX: 防止死循环
          AND (
              datetime(a1.timestamp_end) < datetime(a2.timestamp_start)
              OR 
              (datetime(a1.timestamp_end) = datetime(a2.timestamp_start) AND a1.id < a2.id)
          )

          AND duration.inSeconds(datetime(a1.timestamp_end), datetime(a2.timestamp_start)).seconds < $window

        MATCH (e1)-[:TRIGGERED]->(a1)
        MATCH (e2)-[:TRIGGERED]->(a2)
        WITH a1, a2, e1, e2

        // 关键优化：将最大深度从 15 降为 6，大幅降低内存占用
        MATCH path = shortestPath((e1)-[:Spawn|Write|Read|Inject|Connect|Resolve|Load*1..6]-(e2))

        CALL (a1, a2, path) {
            MERGE (a1)-[r:NEXT_STAGE]->(a2)
            SET r.type = 'causal',
                r.confidence = 'High',
                r.path_length = length(path),
                r.time_gap = duration.inSeconds(datetime(a1.timestamp_end), datetime(a2.timestamp_start)).seconds
        } IN TRANSACTIONS OF 100 ROWS
        """

        self._run_massive_update(causal_query, window=time_window_seconds)
        logging.info("因果推断分析更新完成")