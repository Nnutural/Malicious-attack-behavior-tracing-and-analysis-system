import requests
import logging
from neo4j import GraphDatabase

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class CTILoader:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        # MITRE ATT&CK Enterprise JSON URL
        self.mitre_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

    def close(self):
        self.driver.close()

    def fetch_and_load(self, limit_groups=20):
        """
        :param limit_groups: 限制导入的 APT 组织数量，默认为 20 个，防止内存/数据库压力过大
        """
        logging.info("正在从 MITRE GitHub 下载 ATT&CK 数据...")
        try:
            # MITRE 的文件大约 10MB+，Python 内存完全没问题
            response = requests.get(self.mitre_url)
            if response.status_code != 200:
                logging.error("下载失败")
                return
            stix_data = response.json()
        except Exception as e:
            logging.error(f"网络请求异常: {e}")
            return

        objects = stix_data.get("objects", [])

        # 1. 提取 Group (Intrusion Set) 和 Technique
        groups = {}
        techniques = {}
        relationships = []

        logging.info(f"解析 STIX 数据 ({len(objects)} 对象)...")
        for obj in objects:
            obj_type = obj.get("type")

            if obj_type == "intrusion-set":
                # 提取 APT 组织
                groups[obj.get("id")] = {
                    "name": obj.get("name"),
                    "aliases": obj.get("aliases", []),
                    "description": obj.get("description", "")
                }

            elif obj_type == "attack-pattern":
                # 提取技术 (T1059 等)
                ext_refs = obj.get("external_references", [])
                t_id = next((ref["external_id"] for ref in ext_refs if ref["source_name"] == "mitre-attack"), None)
                if t_id:
                    techniques[obj.get("id")] = {
                        "t_id": t_id,
                        "name": obj.get("name")
                    }

            elif obj_type == "relationship" and obj.get("relationship_type") == "uses":
                relationships.append({
                    "source": obj.get("source_ref"),
                    "target": obj.get("target_ref")
                })

        # ================= [新增：数据量裁剪逻辑] =================
        logging.info(f"原始数据包含 {len(groups)} 个组织，{len(techniques)} 项技术。正在进行裁剪...")

        # 1. 裁剪组织：只保留前 limit_groups 个（或者你可以指定保留特定名字的组织）
        # 提示：为了演示效果，你可以手动把 "Lazarus Group" 或 "APT29" 这种著名的加进去
        target_group_ids = list(groups.keys())[:limit_groups]

        # 裁剪后的 groups 字典
        limited_groups = {k: groups[k] for k in target_group_ids}

        # 2. 裁剪关系：只保留 源头是这些组织的 关系
        # 我们不裁剪 Technique，因为技术是“字典”，量不大且通用，保留全量有助于匹配
        limited_relationships = [
            r for r in relationships
            if r["source"] in limited_groups
        ]

        logging.info(f"裁剪完成：将导入 {len(limited_groups)} 个组织和 {len(limited_relationships)} 条关联关系。")
        # ========================================================

        # 2. 写入 Neo4j (传入裁剪后的数据)
        self._ingest_to_neo4j(limited_groups, techniques, limited_relationships)

    def _ingest_to_neo4j(self, groups, techniques, relationships):
        logging.info("开始写入 Neo4j 知识库...")
        with self.driver.session() as session:
            # 2.1 写入 APT 组织
            group_query = """
            UNWIND $batch AS g
            MERGE (is:IntrusionSet {id: g.name}) // 使用名称作为ID便于匹配
            SET is.aliases = g.aliases,
                is.stix_id = g.stix_id
            """
            group_list = [{"stix_id": k, **v} for k, v in groups.items()]
            self._batch_execute(session, group_query, group_list)

            # 2.2 确保 Technique 存在 (部分可能在 Graph_construct 中未建立)
            tech_query = """
            UNWIND $batch AS t
            MERGE (tech:Technique {id: t.t_id})
            ON CREATE SET tech.name = t.name
            SET tech.stix_id = t.stix_id
            """
            tech_list = [{"stix_id": k, **v} for k, v in techniques.items()]
            self._batch_execute(session, tech_query, tech_list)

            # 2.3 建立 USES 关系
            rel_query = """
            UNWIND $batch AS r
            MATCH (is:IntrusionSet {stix_id: r.source})
            MATCH (tech:Technique {stix_id: r.target})
            MERGE (is)-[:USES]->(tech)
            """
            # 过滤只保留 Group -> Technique 的关系
            valid_rels = [
                r for r in relationships
                if r["source"] in groups and r["target"] in techniques
            ]
            self._batch_execute(session, rel_query, valid_rels)

        logging.info(f"CTI 导入完成: {len(group_list)} 组织, {len(valid_rels)} 关联关系")

    def _batch_execute(self, session, query, data, batch_size=500):
        total = len(data)
        for i in range(0, total, batch_size):
            batch = data[i:i + batch_size]
            session.run(query, batch=batch)


if __name__ == "__main__":
    # 使用前请确保 Neo4j 运行
    loader = CTILoader("bolt://localhost:7687", "neo4j", "00000000")
    loader.fetch_and_load()
    loader.close()