from __future__ import annotations

import hashlib
from typing import Iterable

from neo4j import GraphDatabase


def stable_scenario_id(victim_ip: str, start_time: str) -> str:
    """
    生成稳定 scenario_id：
    - 用 victim_ip + start_time 做 hash，取前 16 位
    - 这样同一 victim 在同一链起点时间基本稳定
    """
    base = f"{victim_ip}|{start_time}"
    return hashlib.sha1(base.encode("utf-8")).hexdigest()[:16]


class ScenarioLinker:
    """
    把 scenario_id 写回 Neo4j 的 AttackEvent 节点：
    SET ae.scenario_id = $sid
    """

    def __init__(self, uri: str, user: str, password: str) -> None:
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self) -> None:
        self.driver.close()

    def set_scenario_id_for_attackevents(self, scenario_id: str, event_ids: Iterable[str]) -> int:
        """
        event_ids 是 AttackEvent.id 列表（注意不是 attack_id 字段）
        返回写入的节点数量
        """
        eids = [str(x) for x in event_ids if x]
        if not scenario_id or not eids:
            return 0

        query = """
        UNWIND $eids AS eid
        MATCH (ae:AttackEvent {id: eid})
        SET ae.scenario_id = $sid
        RETURN count(ae) AS n
        """
        with self.driver.session() as session:
            rec = session.run(query, sid=scenario_id, eids=eids).single()
            return int(rec["n"]) if rec and rec.get("n") is not None else 0