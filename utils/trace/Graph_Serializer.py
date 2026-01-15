from neo4j import GraphDatabase

#-------------------------------------------------------------------------------------------------
# 对接前端 vis-network 。它负责执行 Cypher 查询，并将结果转化为 Nodes/Edges 结构。
#-------------------------------------------------------------------------------------------------
class GraphSerializer:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def get_attack_chain_summary(self, scenario_id):
        """
        【宏观视图】仅展示 ATT&CK 战术/技术的流转
        对应前端需求：重建后的攻击路径（高层级）
        """
        query = """
        MATCH (ae:AttackEvent)
        WHERE ae.scenario_id = $sid
        MATCH (ae)-[:IS_TYPE]->(t:Technique)

        // 查找阶段间的流转关系
        OPTIONAL MATCH (ae)-[r:NEXT_STAGE]->(next_ae:AttackEvent)
        WHERE next_ae.scenario_id = $sid

        RETURN ae, t, r, next_ae
        """
        # Vis.js 格式
        nodes = []
        edges = []
        added_nodes = set()

        with self.driver.session() as session:
            result = session.run(query, sid=scenario_id)
            for record in result:
                ae = record['ae']
                t = record['t']

                # 构建节点 (以 Technique 为核心展示)
                node_id = ae['id']
                if node_id not in added_nodes:
                    nodes.append({
                        "id": node_id,
                        "label": t['name'],  # 节点显示技术名称
                        "group": "technique",
                        "title": f"TID: {t['id']}\nTime: {ae['timestamp_start']}",  # 鼠标悬停详情
                        "stage": ae.get('stage_order', 0)
                    })
                    added_nodes.add(node_id)

                # 构建边
                next_ae = record['next_ae']
                if next_ae:
                    edges.append({
                        "from": node_id,
                        "to": next_ae['id'],
                        "arrows": "to",
                        "label": record['r'].get('type', 'next')
                    })

        return {"nodes": nodes, "edges": edges}

    def get_scenario_topology(self, scenario_id):
        """
        【微观视图】展示底层的实体拓扑 (Process, File, IP)
        修正：移除对 related 节点的 TRIGGERED 强校验，显示完整的上下文路径
        修正：修复 unhashable type: 'dict' 错误，改用 ID 去重
        """
        query = """
        MATCH (ae:AttackEvent {scenario_id: $sid})
        MATCH (entity)-[:TRIGGERED]->(ae)

        // 1. 核心实体：触发了告警的节点
        WITH collect(DISTINCT entity) AS core_entities

        // 2. 上下文扩展：查找与核心实体有直接关系的节点
        UNWIND core_entities AS start_node
        OPTIONAL MATCH path = (start_node)-[r:Spawn|Write|Read|Connect|Inject|Resolve|Load]-(related)

        RETURN start_node AS entity, collect(path) AS paths
        """

        nodes = {}
        # 注意：这里我们不需要列表了，直接用字典 edges_map 来存，key 是边的 ID，天然去重
        edges_map = {}

        with self.driver.session() as session:
            result = session.run(query, sid=scenario_id)
            for record in result:
                # 1. 处理核心告警实体
                self._process_node(record['entity'], nodes)

                # 2. 处理扩展路径
                paths = record['paths']
                if paths:
                    for p in paths:
                        for rel in p.relationships:
                            src = rel.start_node
                            dst = rel.end_node

                            # 将关联的“背景节点”也加入节点列表
                            self._process_node(src, nodes)
                            self._process_node(dst, nodes)

                            # 生成唯一的边 ID
                            edge_key = f"{src['id']}_{rel.type}_{dst['id']}"

                            # 直接用 ID 作为 key 存入字典，实现去重
                            if edge_key not in edges_map:
                                edges_map[edge_key] = {
                                    "id": edge_key,
                                    "from": src['id'],
                                    "to": dst['id'],
                                    "label": rel.type,
                                    "arrows": "to",
                                    # 字典结构在这里是允许的，因为我们不再用 set 去重了
                                    "color": {"color": "#ff0000"} if rel.type in ['Inject', 'Connect'] else "#848484"
                                }

        # 将去重后的字典值转回列表
        return {"nodes": list(nodes.values()), "edges": list(edges_map.values())}

    def _process_node(self, neo4j_node, nodes_dict):
        """辅助函数：处理 Neo4j 节点转 Vis.js 格式，包含样式配置"""
        n_id = neo4j_node.get('id')  # 使用你的唯一标识
        if n_id in nodes_dict:
            return

        labels = list(neo4j_node.labels)
        main_label = labels[0] if labels else "Unknown"

        # 样式映射
        icon_map = {
            "Process": "⚙️",
            "File": "📄",
            "IP": "🌐",
            "Domain": "🔗",
            "Registry": "®️",
            "User": "👤"
        }

        # 构造 Label 显示
        display_label = n_id
        if main_label == "Process":
            display_label = f"{icon_map['Process']} {neo4j_node.get('name')}\n({neo4j_node.get('pid')})"
        elif main_label == "File":
            display_label = f"{icon_map['File']} {neo4j_node.get('name')}"
        elif main_label == "IP":
            display_label = f"{icon_map['IP']} {neo4j_node.get('ip')}"

        nodes_dict[n_id] = {
            "id": n_id,
            "label": display_label,
            "group": main_label,
            "title": str(dict(neo4j_node)),  # 悬停显示全部属性
            "shape": "box"
        }