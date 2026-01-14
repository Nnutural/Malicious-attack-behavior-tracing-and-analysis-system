import logging
from neo4j import GraphDatabase

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class GraphIngestionEngine:
    def __init__(self, uri, user, password,initial_pid_cache=None):
        """
        初始化 Neo4j 连接
        """
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        # [修复1] 内存缓存：记录 (Host, PID) -> Timestamp 的映射
        self.pid_cache = initial_pid_cache if initial_pid_cache else {}

    # 新增一个方法供外部获取最新缓存
    def get_current_pid_cache(self):
        return self.pid_cache

    def close(self):
        """
        关闭数据库连接
        """
        self.driver.close()

    def _generate_process_id(self, host_ip, pid, timestamp=None):
        """
        生成进程唯一标识 ID
        逻辑：HostIP_PID_CreateTime
        """
        # [关键修改] 使用字符串作为 Key，而不是元组 (host_ip, pid)
        # 这样 json.dump 才能正常保存
        key = f"{host_ip}_{pid}"

        if timestamp and timestamp != "unknown":
            self.pid_cache[key] = timestamp
            time_suffix = timestamp
        else:
            # 如果缓存里也没有，默认为 unknown
            time_suffix = self.pid_cache.get(key, "unknown")

        return f"{host_ip}_{pid}_{time_suffix}"

    def ingest_host_behavior(self, data_list):
        """
        处理主机行为数据 (host_behavior) - [修改版]
        功能：
        1. 构建进程树 (Process -[Spawn]-> Process) [含 Hash]
        2. 构建文件操作 (Process -[Write/Read/Delete]-> File) [含 Hash]
        3. 构建注册表操作 (Process -[Write]-> Registry) [新增]
        4. 构建进程网络连接 (Process -[Connect]-> IP) [新增]
        5. 构建注入与加载 (Process -[Inject]-> Process, Process -[Load]-> File) [新增]
        """
        if not data_list:
            return

        # [修复1] 预处理：先遍历一遍找出所有的 process_create 事件，建立 PID 缓存
        for item in data_list:
            if item.get("event_type") == "process_create":
                entities = item.get("entities", {})
                self._generate_process_id(item.get("host_ip"), entities.get("pid"), item.get("timestamp"))

        with self.driver.session() as session:
            # 预处理数据：增加通用字段并计算ID
            processed_data = []
            for item in data_list:
                entities = item.get("entities", {})
                features = item.get("behavior_features", {})

                # ID 生成逻辑会自动查找缓存
                ts_for_id = item.get("timestamp") if item.get("event_type") == "process_create" else None
                proc_id = self._generate_process_id(item.get("host_ip"), entities.get("pid"), ts_for_id)

                event_data = {
                    "host_ip": item.get("host_ip"),
                    "timestamp": item.get("timestamp"),
                    "event_type": item.get("event_type"),
                    "entities": entities,  # 保留原始实体字典以便后续按需提取
                    "features": features,
                    # 通用进程信息
                    "pid": entities.get("pid"),
                    "proc_name": entities.get("process_name"),
                    "proc_hash": entities.get("hash"),  # [新增] 进程Hash
                    "proc_id": proc_id
                }
                processed_data.append(event_data)

            # ----------------------------------------------
            # 1. 进程创建 (Spawn) - [已更新 Hash]
            # ----------------------------------------------
            spawn_query = """
            UNWIND $events AS event
            WITH event WHERE event.event_type = 'process_create' AND event.pid IS NOT NULL

            // 父进程 (Source)
            // [修复2] 创建父进程时，写入名称，避免报告中出现 root_process: null
            MERGE (p:Process {id: event.parent_id})
            ON CREATE SET p.name = event.entities.parent_process
            
            // 子进程 (Target)
            MERGE (c:Process {id: event.proc_id})
            ON CREATE SET 
                c.name = event.proc_name,
                c.pid = event.pid,
                c.cmdline = event.entities.command_line,
                c.host = event.host_ip,
                c.timestamp = event.timestamp,
                c.hash = event.proc_hash  

            // 建立 Spawn 关系
            MERGE (p)-[r:Spawn]->(c)
            SET r.timestamp = event.timestamp,
                r.is_abnormal = event.features.is_abnormal_parent
            """

            # 针对 Spawn 需要预先计算 parent_id
            spawn_data = []
            for d in processed_data:
                if d["event_type"] == "process_create":
                    d["parent_id"] = f"{d['host_ip']}_{d['entities'].get('parent_pid')}_unknown"
                    spawn_data.append(d)
            if spawn_data:
                session.execute_write(lambda tx: tx.run(spawn_query, events=spawn_data))

            # ----------------------------------------------
            # 2. 文件操作 (Write/Read/Delete) & 加载 (Load) - [已更新 Hash]
            # ----------------------------------------------
            # 映射表增加 image_load
            file_ops_map = {
                "file_create": "Write",
                "file_modify": "Write",
                "file_delete": "Delete",
                "file_read": "Read",
                "image_load": "Load"  # [新增] 对应 DLL/Image 加载
            }

            for evt_type, relation in file_ops_map.items():
                file_query = f"""
                UNWIND $events AS event
                WITH event WHERE event.event_type = '{evt_type}'

                MERGE (p:Process {{id: event.proc_id}})

                // 文件节点 (HostIP + FilePath)
                MERGE (f:File {{id: event.host_ip + '_' + event.entities.file_path}})
                ON CREATE SET 
                    f.path = event.entities.file_path,
                    f.name = event.entities.file_name,
                    f.host = event.host_ip,
                    f.hash = event.entities.hash  // [新增] 存入 Hash

                MERGE (p)-[r:{relation}]->(f)
                SET r.timestamp = event.timestamp
                """
                # 过滤数据
                batch_data = [d for d in processed_data if
                              d["event_type"] == evt_type and d["entities"].get("file_path")]
                if batch_data:
                    session.execute_write(lambda tx: tx.run(file_query, events=batch_data))

            # ----------------------------------------------
            # 3. 注册表操作 (Write Registry) - [新增]
            # ----------------------------------------------
            reg_query = """
            UNWIND $events AS event
            WITH event WHERE event.event_type = 'registry_set_value'

            MERGE (p:Process {id: event.proc_id})

            // 注册表节点 (直接用 KeyPath 做 ID)
            MERGE (r:Registry {id: event.entities.registry_key})
            ON CREATE SET 
                r.key = event.entities.registry_key,
                r.value_name = event.entities.registry_value_name,
                r.value_data = event.entities.registry_value_data

            MERGE (p)-[rel:Write]->(r)
            SET rel.timestamp = event.timestamp
            """
            reg_data = [d for d in processed_data if d["event_type"] == "registry_set_value"]
            if reg_data:
                session.execute_write(lambda tx: tx.run(reg_query, events=reg_data))

            # ----------------------------------------------
            # 4. 进程网络连接 (Process -> Connect -> IP) - [新增]
            # ----------------------------------------------
            # 注意：这是主机侧视角的网络连接，能关联到具体进程 PID
            net_conn_query = """
            UNWIND $events AS event
            WITH event WHERE event.event_type = 'network_connection'

            MERGE (p:Process {id: event.proc_id})
            MERGE (ip:IP {id: event.entities.dst_ip})
            ON CREATE SET ip.ip = event.entities.dst_ip

            MERGE (p)-[r:Connect]->(ip)
            SET r.timestamp = event.timestamp,
                r.dst_port = event.entities.dst_port
            """
            net_data = [d for d in processed_data if
                        d["event_type"] == "network_connection" and d["entities"].get("dst_ip")]
            if net_data:
                session.execute_write(lambda tx: tx.run(net_conn_query, events=net_data))

            # ----------------------------------------------
            # 5. 进程注入 (Process -> Inject -> Process) - [新增]
            # ----------------------------------------------
            inject_query = """
            UNWIND $events AS event
            WITH event WHERE event.event_type = 'process_injection'

            MERGE (src:Process {id: event.proc_id})

            // 目标进程 (被注入者)
            // 假设 entities 中含有 target_pid
            MERGE (target:Process {id: event.target_proc_id})

            MERGE (src)-[r:Inject]->(target)
            SET r.timestamp = event.timestamp,
                r.is_memory_injection = true
            """
            inject_data = []
            for d in processed_data:
                if d["event_type"] == "process_injection" and d["entities"].get("target_pid"):
                    # 为目标进程生成 ID (时间未知)
                    d["target_proc_id"] = self._generate_process_id(d["host_ip"], d["entities"].get("target_pid"),
                                                                    "unknown")
                    inject_data.append(d)
            if inject_data:
                session.execute_write(lambda tx: tx.run(inject_query, events=inject_data))

            logging.info(f"已处理 {len(processed_data)} 条主机行为数据 - 覆盖注册表/网络/文件/注入")

    def ingest_network_traffic(self, data_list):
        """
        处理网络流量数据 (network_traffic)
        功能：
        1. 构建 IP 通信 (IP -[Traffic_Flow]-> IP)
        2. 构建 DNS 解析 (IP -[Resolve]-> Domain)
        """
        if not data_list:
            return

        with self.driver.session() as session:
            processed_data = []
            for item in data_list:
                entities = item.get("entities", {})
                processed_data.append({
                    "src_ip": item.get("src_ip"),
                    "dst_ip": item.get("dst_ip"),
                    "timestamp": item.get("timestamp"),
                    "event_type": item.get("event_type"),
                    "domain": entities.get("domain"),
                    "protocol": item.get("protocol"),
                    "features": item.get("traffic_features", {})
                })

            # 1. 常规 IP 通信 (Traffic_Flow)
            flow_query = """
            UNWIND $events AS event
            WITH event WHERE event.src_ip IS NOT NULL AND event.dst_ip IS NOT NULL

            MERGE (src:IP {id: event.src_ip}) SET src.ip = event.src_ip
            MERGE (dst:IP {id: event.dst_ip}) SET dst.ip = event.dst_ip

            MERGE (src)-[r:Traffic_Flow]->(dst)
            SET r.timestamp = event.timestamp,
                r.protocol = event.protocol,
                r.event_type = event.event_type,
                r.is_covert = event.features.is_covert_channel,
                r.channel_type = event.features.channel_type
            """
            session.execute_write(lambda tx: tx.run(flow_query, events=processed_data))

            # 2. DNS 解析 (Resolve)
            dns_query = """
            UNWIND $events AS event
            WITH event WHERE event.domain IS NOT NULL

            MERGE (src:IP {id: event.src_ip})
            MERGE (d:Domain {id: event.domain})
            ON CREATE SET d.name = event.domain

            MERGE (src)-[r:Resolve]->(d)
            SET r.timestamp = event.timestamp,
                r.query_type = event.features.query_type,
                r.is_suspicious = event.features.is_covert_channel
            """
            session.execute_write(lambda tx: tx.run(dns_query, events=processed_data))
            logging.info(f"已处理 {len(processed_data)} 条流量数据 - 网络图谱构建")

    def ingest_host_log(self, data_list):
        """
        处理主机日志数据 (host_log)
        功能：
        1. 登录会话重建 (User -[Logon]-> IP)
        2. 源IP关联 (IP(Src) -[Logon_Source]-> IP(Host))
        """
        if not data_list:
            return

        with self.driver.session() as session:
            processed_data = []
            for item in data_list:
                entities = item.get("entities", {})
                if item.get("event_type") == "user_logon":
                    processed_data.append({
                        "host_ip": item.get("host_ip"),
                        "timestamp": item.get("timestamp"),
                        "user": entities.get("user"),
                        "src_ip": entities.get("src_ip")
                    })

            logon_query = """
            UNWIND $events AS event
            WITH event WHERE event.user IS NOT NULL

            // 用户节点
            MERGE (u:User {id: event.host_ip + '_' + event.user})
            ON CREATE SET u.username = event.user

            // 主机 IP 节点
            MERGE (host:IP {id: event.host_ip}) SET host.ip = event.host_ip

            // User -> Logon -> Host
            MERGE (u)-[r:Logon]->(host)
            SET r.timestamp = event.timestamp

            // (可选) 溯源：Source IP -> Host
            FOREACH (ignoreMe IN CASE WHEN event.src_ip IS NOT NULL THEN [1] ELSE [] END |
                MERGE (src:IP {id: event.src_ip})
                ON CREATE SET src.ip = event.src_ip
                MERGE (src)-[rel:Logon_Source]->(host)
                SET rel.timestamp = event.timestamp, rel.user = event.user
            )
            """
            session.execute_write(lambda tx: tx.run(logon_query, events=processed_data))
            logging.info(f"已处理 {len(processed_data)} 条登录日志")

    def ingest_attack_events(self, attack_data_list):
        """
        处理 ATT&CK 攻击检测数据 (与原版逻辑基本保持一致，确保 TRIGGERED 关系正确)
        """
        if not attack_data_list:
            return

        query = """
        UNWIND $batch AS data

        // 1. 知识层
        MERGE (t:Technique {id: data.technique.id})
        ON CREATE SET 
            t.name = data.technique.name,
            t.tactic_id = data.tactic.id,
            t.tactic_name = data.tactic.name

        // 2. 检测层
        MERGE (ae:AttackEvent {id: data.attack_id})
        ON CREATE SET 
            ae.confidence = data.confidence,
            ae.timestamp_start = data.timestamp_start,
            ae.timestamp_end = data.timestamp_end,
            ae.stage_order = data.stage_order,
            ae.victim_ip = data.victim_ip

        MERGE (ae)-[:IS_TYPE]->(t)

        // 3. 关联实体证据 (Process, File, Registry, IP, User)
        WITH ae, data.related_events AS evidence_ids
        UNWIND evidence_ids AS eid

        // 尝试匹配 Process        
        // 尝试精确匹配
        OPTIONAL MATCH (exact_p:Process {id: eid})
        FOREACH (_ IN CASE WHEN exact_p IS NOT NULL THEN [1] ELSE [] END | MERGE (exact_p)-[:TRIGGERED]->(ae))
        WITH ae, eid
        
        // [新增] 模糊匹配补偿 (当 ID 是 host_pid_unknown 但数据库里存的是具体时间时)
        // 假设 eid 格式为 'IP_PID_unknown'
        OPTIONAL MATCH (fuzzy_p:Process)
        WHERE eid ENDS WITH 'unknown' 
          AND fuzzy_p.id STARTS WITH split(eid, '_unknown')[0] 
          //AND fuzzy_p.host = data.victim_ip
        FOREACH (_ IN CASE WHEN fuzzy_p IS NOT NULL THEN [1] ELSE [] END | MERGE (fuzzy_p)-[:TRIGGERED]->(ae))
        WITH ae, eid
        
           
        // [修复3] 补充 Domain 的关联
        OPTIONAL MATCH (d:Domain {id: eid})
        FOREACH (_ IN CASE WHEN d IS NOT NULL THEN [1] ELSE [] END | MERGE (d)-[:TRIGGERED]->(ae))
        WITH ae, eid
        
        // 尝试匹配 File
        OPTIONAL MATCH (f:File {id: eid})
        FOREACH (_ IN CASE WHEN f IS NOT NULL THEN [1] ELSE [] END | MERGE (f)-[:TRIGGERED]->(ae))
        WITH ae, eid

        // 尝试匹配 Registry [新增]
        OPTIONAL MATCH (r:Registry {id: eid})
        FOREACH (_ IN CASE WHEN r IS NOT NULL THEN [1] ELSE [] END | MERGE (r)-[:TRIGGERED]->(ae))
        WITH ae, eid

        // 尝试匹配 IP
        OPTIONAL MATCH (i:IP {id: eid})
        FOREACH (_ IN CASE WHEN i IS NOT NULL THEN [1] ELSE [] END | MERGE (i)-[:TRIGGERED]->(ae))
        """

        try:
            with self.driver.session() as session:
                session.execute_write(lambda tx: tx.run(query, batch=attack_data_list))
            logging.info(f"已处理 {len(attack_data_list)} 条 ATT&CK 事件关联")
        except Exception as e:
            logging.error(f"处理攻击事件数据时发生错误: {e}")

        chain_query = """
        MATCH (a1:AttackEvent), (a2:AttackEvent)
        WHERE a1.victim_ip = a2.victim_ip
          AND a1.attack_id <> a2.attack_id
          // 确保 a1 在 a2 之前
          AND datetime(a1.timestamp_end) <= datetime(a2.timestamp_start)
          // 限制时间窗口 (例如：两个阶段间隔不超过 2 小时)
          AND duration.inSeconds(datetime(a1.timestamp_end), datetime(a2.timestamp_start)).seconds < 7200
          // 确保阶段逻辑递进 (例如：初始访问 -> 执行)
          AND a1.stage_order < a2.stage_order

        MERGE (a1)-[r:NEXT_STAGE]->(a2)
        SET r.time_gap_seconds = duration.inSeconds(datetime(a1.timestamp_end), datetime(a2.timestamp_start)).seconds
        """

        # 执行链接
        try:
            with self.driver.session() as session:
                session.run(chain_query)
            logging.info("已构建攻击阶段的时序关联 (NEXT_STAGE)")
        except Exception as e:
            logging.error(f"构建攻击链失败: {e}")

# ==========================================
# 测试代码
# ==========================================
if __name__ == "__main__":
    # 模拟包含 注册表 和 进程连接 的行为数据
    mock_behavior_data = [
        {
            "data_source": "host_behavior",
            "timestamp": "2023-10-27T10:06:00Z",
            "host_ip": "192.168.1.100",
            "event_type": "registry_set_value",
            "entities": {
                "process_name": "malware.exe",
                "pid": 5555,
                "registry_key": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Evil",
                "registry_value_name": "Evil",
                "registry_value_data": "C:\\Temp\\malware.exe"
            },
            "behavior_features": {}
        },
        {
            "data_source": "host_behavior",
            "timestamp": "2023-10-27T10:07:00Z",
            "host_ip": "192.168.1.100",
            "event_type": "file_create",
            "entities": {
                "process_name": "malware.exe",
                "pid": 5555,
                "file_path": "C:\\Temp\\dropped.dll",
                "file_name": "dropped.dll",
                "hash": "a1b2c3d4e5f6..."  # 测试 Hash 导入
            }
        }
    ]

    engine = GraphIngestionEngine("bolt://localhost:7687", "neo4j", "00000000")
    try:
        print("开始导入扩展后的数据...")
        engine.ingest_host_behavior(mock_behavior_data)
        print("导入完成。")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        engine.close()