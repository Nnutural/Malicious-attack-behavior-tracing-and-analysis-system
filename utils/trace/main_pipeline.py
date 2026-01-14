# main_pipeline.py（写回 Neo4j scenario_id + 默认 SecurityTraceDB）
import logging
import time

from utils.trace.DB_Connector import SQLServerLoader
from utils.trace.Graph_construct import GraphIngestionEngine
from utils.trace.Attck_Map import ATTACKMapper
from utils.trace.StateManager import StateManager
from utils.trace.APT_Analysis_Engine import APTAnalysisEngine

from utils.trace.service.scenario_linker import ScenarioLinker, stable_scenario_id

STOP_FLAG = False


def run_ingestion_cycle():
    # 1) SQL Server：改为 SecurityTraceDB（你现在已经在这个库建表了）
    db_loader = SQLServerLoader("10.21.211.11,1433", "sa", "000000", "SecurityTraceDB")

    mapper = ATTACKMapper("attack_rules.yaml")
    state_mgr = StateManager()

    neo4j_uri = "bolt://localhost:7687"
    neo4j_user = "neo4j"
    neo4j_pass = "00000000"

    graph_engine = GraphIngestionEngine(
        neo4j_uri, neo4j_user, neo4j_pass,
        initial_pid_cache=state_mgr.get_pid_cache()
    )

    scenario_linker = ScenarioLinker(neo4j_uri, neo4j_user, neo4j_pass)

    try:
        logging.info("=== 开始新一轮数据采集与构图循环 ===")

        # HostBehaviors
        last_id = state_mgr.get_checkpoint("HostBehaviors")
        behaviors, new_id = db_loader.fetch_new_data("HostBehaviorTable", last_id)

        if behaviors:
            logging.info(f"读取到 {len(behaviors)} 条新主机行为数据")
            graph_engine.ingest_host_behavior(behaviors)

            detected_attacks = []
            for event in behaviors:
                detected_attacks.extend(mapper.analyze_event(event))
            if detected_attacks:
                graph_engine.ingest_attack_events(detected_attacks)

            state_mgr.update_checkpoint("HostBehaviors", new_id)

        # NetworkTraffic
        last_id_net = state_mgr.get_checkpoint("NetworkTraffic")
        traffic_data, new_id_net = db_loader.fetch_new_data("NetworkTrafficTable", last_id_net)

        if traffic_data:
            logging.info(f"读取到 {len(traffic_data)} 条新流量数据")
            graph_engine.ingest_network_traffic(traffic_data)

            detected_attacks = []
            for event in traffic_data:
                detected_attacks.extend(mapper.analyze_event(event))
            if detected_attacks:
                graph_engine.ingest_attack_events(detected_attacks)

            state_mgr.update_checkpoint("NetworkTraffic", new_id_net)

        # HostLogs（你后续可以补：db_loader.fetch_new_data("HostLogs", ...) + graph_engine.ingest_host_log）

        # build chains
        graph_engine.build_causal_chains(time_window_seconds=7200)
        state_mgr.update_pid_cache(graph_engine.get_current_pid_cache())
        state_mgr.save_state()

        # APT 分析引擎生成报告
        analysis_engine = APTAnalysisEngine(neo4j_uri, neo4j_user, neo4j_pass)
        reports = analysis_engine.run_pipeline()

        # 关键：写回 Neo4j scenario_id，并让 SQL AttackReports 用稳定 sid
        for report in reports:
            victim_ip = report.get("victim_ip") or ""
            time_window = report.get("time_window") or ""
            start_time = time_window.split(" to ", 1)[0] if " to " in time_window else ""

            # 1) 稳定 scenario_id
            sid = stable_scenario_id(str(victim_ip), str(start_time))
            report["scenario_id"] = sid

            # 2) 写回 Neo4j：需要该场景的 AttackEvent.id 列表
            # report.attack_chain 只有 technique_name，不够；但 report 里没有事件id列表。
            # 所以我们在这里用 victim_ip + time window 再去 Neo4j 查出该链的事件 id：
            # （这是写回时的“桥接查询”，不改核心逻辑）
            try:
                event_ids = _get_attackevent_ids_for_window(
                    uri=neo4j_uri, user=neo4j_user, password=neo4j_pass,
                    victim_ip=str(victim_ip), start_time=str(start_time),
                    end_time=time_window.split(" to ", 1)[1] if " to " in time_window else ""
                )
                n = scenario_linker.set_scenario_id_for_attackevents(sid, event_ids)
                logging.info(f"[scenario_link] sid={sid} -> AttackEvent 写入 {n} 个节点")
            except Exception as exc:
                logging.warning(f"[scenario_link] 写回 scenario_id 失败: {exc}")

            # 3) 存 SQL Server AttackReports
            db_loader.save_analysis_report(report)

        analysis_engine.close()

    except Exception as e:
        logging.error(f"Pipeline 运行异常: {e}")
    finally:
        try:
            scenario_linker.close()
        except Exception:
            pass
        db_loader.close()
        graph_engine.close()


def _get_attackevent_ids_for_window(*, uri: str, user: str, password: str, victim_ip: str, start_time: str, end_time: str) -> list[str]:
    """
    桥接查询：根据 victim_ip + 时间窗，在 Neo4j 找出该窗内的 AttackEvent.id
    用于写回 scenario_id（方案A）
    """
    from neo4j import GraphDatabase

    if not victim_ip or not start_time or not end_time:
        return []

    q = """
    MATCH (ae:AttackEvent)
    WHERE ae.victim_ip = $vip
      AND datetime(ae.timestamp_start) >= datetime($ts0)
      AND datetime(ae.timestamp_start) <= datetime($ts1)
    RETURN ae.id AS id
    ORDER BY ae.timestamp_start ASC
    """
    driver = GraphDatabase.driver(uri, auth=(user, password))
    try:
        with driver.session() as session:
            rows = session.run(q, vip=victim_ip, ts0=start_time, ts1=end_time).data()
            return [r["id"] for r in rows if r.get("id")]
    finally:
        driver.close()


def pipeline_loop():
    global STOP_FLAG
    logging.info("后台分析任务已启动")
    while not STOP_FLAG:
        try:
            run_ingestion_cycle()
        except Exception as e:
            logging.error(f"Pipeline 循环发生错误: {e}")
        for _ in range(60):
            if STOP_FLAG:
                break
            time.sleep(1)
    logging.info("后台分析任务已停止")