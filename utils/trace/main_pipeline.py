# main_pipeline.py (修改版)
import logging
import time
import threading  # 引入线程
from DB_Connector import SQLServerLoader
from Graph_construct import GraphIngestionEngine
from Attck_Map import ATTACKMapper
from StateManager import StateManager
from APT_Analysis_Engine import APTAnalysisEngine

# 全局控制开关
STOP_FLAG = False


def run_ingestion_cycle():
    # 1. 初始化所有组件
    # 数据库连接 (对应流程图 A)
    db_loader = SQLServerLoader("10.21.211.11,1433", "sa", "000000", "APT_Intelligence")

    # ATT&CK 映射器 (对应流程图 C & D)
    # 确保 attack_rules.yaml 在当前目录下
    mapper = ATTACKMapper("attack_rules.yaml")

    # 状态管理器 (用于记录读取进度)
    state_mgr = StateManager()

    # 图构建引擎 (对应流程图 F & G)
    # 注意：这里我们传入 StateManager 获取的缓存，保持 PID 映射的一致性
    graph_engine = GraphIngestionEngine(
        "bolt://localhost:7687", "neo4j", "00000000",
        initial_pid_cache=state_mgr.get_pid_cache()
    )

    try:
        logging.info("=== 开始新一轮数据采集与构图循环 ===")

        # =========================================================
        # 第一步：处理主机行为数据 (Host Behavior)
        # =========================================================
        last_id = state_mgr.get_checkpoint("HostBehaviors")
        # 从 SQL Server 获取新数据
        behaviors, new_id = db_loader.fetch_new_data("HostBehaviorTable", last_id)

        if behaviors:
            logging.info(f"读取到 {len(behaviors)} 条新主机行为数据")

            # 1.1 原始实体入图 (流程图 B -> F)
            # 构建 Process, File, Registry 节点
            graph_engine.ingest_host_behavior(behaviors)

            # 1.2 ATT&CK 规则匹配 (流程图 B -> C -> E)
            detected_attacks = []
            for event in behaviors:
                # analyze_event 返回的是一个列表 (可能命中多条规则)
                matches = mapper.analyze_event(event)
                detected_attacks.extend(matches)

            # 1.3 告警数据入图 (流程图 E -> F)
            # 构建 AttackEvent 节点，并建立 TRIGGERED 关系
            if detected_attacks:
                graph_engine.ingest_attack_events(detected_attacks)

            # 更新断点
            state_mgr.update_checkpoint("HostBehaviors", new_id)

        # =========================================================
        # 第二步：处理网络流量数据 (Network Traffic)
        # =========================================================
        last_id_net = state_mgr.get_checkpoint("NetworkTraffic")
        traffic_data, new_id_net = db_loader.fetch_new_data("NetworkTrafficTable", last_id_net)

        if traffic_data:
            logging.info(f"读取到 {len(traffic_data)} 条新流量数据")

            # 2.1 原始实体入图 (IP, Domain, Traffic_Flow)
            graph_engine.ingest_network_traffic(traffic_data)

            # 2.2 ATT&CK 规则匹配
            detected_attacks = []
            for event in traffic_data:
                matches = mapper.analyze_event(event)
                detected_attacks.extend(matches)

            # 2.3 告警数据入图
            if detected_attacks:
                graph_engine.ingest_attack_events(detected_attacks)

            state_mgr.update_checkpoint("NetworkTraffic", new_id_net)

        # =========================================================
        # 第三步：处理主机日志 (Host Log)
        # =========================================================
        # (逻辑同上，略写)
        # ... fetch -> ingest_host_log -> mapper.analyze -> ingest_attack_events ...

        # =========================================================
        # 第四步：构建因果关联与保存状态
        # =========================================================
        # 此时图谱中已经有了实体和孤立的 AttackEvents
        # 我们需要基于时间窗口和路径可达性，链接 AttackEvent -> NEXT_STAGE -> AttackEvent
        graph_engine.build_causal_chains(time_window_seconds=7200)

        # 更新 PID 缓存到文件，供下次使用
        state_mgr.update_pid_cache(graph_engine.get_current_pid_cache())
        state_mgr.save_state()

        # =========================================================
        # 第五步：触发 APT 分析引擎 (生成最终报告)
        # =========================================================
        # 这就是我们在上一个回答中讨论的部分：从构建好的图里提取场景并生成报告
        analysis_engine = APTAnalysisEngine("bolt://localhost:7687", "neo4j", "00000000")
        reports = analysis_engine.run_pipeline()

        # 将报告存回 SQL Server (供前端查询)
        for report in reports:
            db_loader.save_analysis_report(report)

        analysis_engine.close()

    except Exception as e:
        logging.error(f"Pipeline 运行异常: {e}")
    finally:
        db_loader.close()
        graph_engine.close()


def pipeline_loop():
    """
    循环运行的主入口，供 Flask 线程调用
    """
    global STOP_FLAG
    logging.info("后台分析任务已启动")

    while not STOP_FLAG:
        try:
            run_ingestion_cycle()  # 执行一次完整流程
        except Exception as e:
            logging.error(f"Pipeline 循环发生错误: {e}")

        # 休眠 60 秒，但每秒检查一次是否需要停止（实现快速响应停止指令）
        for _ in range(60):
            if STOP_FLAG: break
            time.sleep(1)

    logging.info("后台分析任务已停止")