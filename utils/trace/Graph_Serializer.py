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
        对应前端需求：底层的实体拓扑图
        """
        query = """
        MATCH (ae:AttackEvent {scenario_id: $sid})
        // 找到该攻击事件触发的所有实体
        MATCH (entity)-[:TRIGGERED]->(ae)

        // 找到实体之间的底层关系 (1-2跳)
        OPTIONAL MATCH path = (entity)-[:Spawn|Write|Read|Connect|Inject|Resolve|Load*1..2]-(related)
        WHERE (related)-[:TRIGGERED]->(:AttackEvent {scenario_id: $sid})

        RETURN entity, path
        """

        nodes = {}
        edges = []

        with self.driver.session() as session:
            result = session.run(query, sid=scenario_id)
            for record in result:
                # 处理起始实体
                self._process_node(record['entity'], nodes)

                # 处理路径
                path = record['path']
                if path:
                    for rel in path.relationships:
                        src = rel.start_node
                        dst = rel.end_node
                        self._process_node(src, nodes)
                        self._process_node(dst, nodes)

                        edge_key = f"{src['id']}_{rel.type}_{dst['id']}"
                        edges.append({
                            "id": edge_key,
                            "from": src['id'],
                            "to": dst['id'],
                            "label": rel.type,
                            "arrows": "to",
                            "color": {"color": "#ff0000"} if rel.type in ['Inject', 'Connect'] else "#848484"
                        })

        # 去重边
        unique_edges = [dict(t) for t in {tuple(d.items()) for d in edges}]
        return {"nodes": list(nodes.values()), "edges": unique_edges}

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