from flask import Flask, jsonify, request
from DB_Connector import SQLServerLoader
from Graph_Serializer import GraphSerializer
import json
import logging
import threading
from flask import Flask, jsonify
# 引入刚才改造的 main_pipeline
import main_pipeline

app = Flask(__name__)

# 配置 (建议移至配置文件)
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = "00000000"
SQL_HOST = "10.21.211.11,1433"
SQL_USER = "sa"
SQL_PASS = "000000"
SQL_DB = "APT_Intelligence"

# 初始化连接器
serializer = GraphSerializer(NEO4J_URI, NEO4J_USER, NEO4J_PASS)


def get_sql_conn():
    return SQLServerLoader(SQL_HOST, SQL_USER, SQL_PASS, SQL_DB)


# -----------------------------------------------------------------
# 辅助逻辑：攻击者指纹与 C2 清洗
# -----------------------------------------------------------------

def parse_c2_info(raw_infrastructure):
    """
    【问题3回答】后端清洗 C2 数据，返回给前端结构化字段
    """
    structured_c2 = []

    # 提取 VT 原始数据
    vt_info = raw_infrastructure.get('vt_info', {})
    if not vt_info:
        return []

    # 1. 基础 C2 节点
    domain = vt_info.get('domain')

    # 2. 结构化 Whois (通常 Raw Whois 是一大段文本，这里模拟提取)
    # 实际项目中可以使用正则表达式从 vt_info['whois_raw'] 中提取 Email 和 注册商
    whois_data = {
        "registrar": vt_info.get('registrar', 'Unknown'),
        "creation_date": vt_info.get('creation_date', 'Unknown'),
        "tags": vt_info.get('tags', [])
    }

    # 3. 历史解析记录 (Passive DNS)
    history_ip = vt_info.get('last_dns_records', [])

    structured_c2.append({
        "type": "C2 Domain",
        "value": domain,
        "risk_score": vt_info.get('reputation_score', 0),
        "whois": whois_data,
        "history_resolution": history_ip[:5]  # 只取最近5条
    })

    return structured_c2


def generate_attacker_fingerprint(report):
    """
    【问题2回答】生成攻击者指纹
    指纹组成：使用的 TTP 集合 + 基础设施特征 (Subnet/Registrar) + 常用文件名
    """
    # 这里我们从报告的 Infrastructure 和 Attack Chain 中提取
    fingerprint = {
        "ttps": report.get('attack_chain', []),  # 攻击技术序列
        "tools": [],
        "c2_pattern": []
    }

    # 尝试从 files 中提取工具指纹 (假设 infra 里有 hashes)
    hashes = report.get('infrastructure', {}).get('hashes', [])
    if hashes:
        fingerprint['tools'] = [{"type": "Hash", "value": h} for h in hashes]

    return fingerprint


# -----------------------------------------------------------------
# API 路由
# -----------------------------------------------------------------

@app.route('/api/reports', methods=['GET'])
def list_reports():
    """
    【问题6回答】分页与筛选
    Query Params: page, limit, start_time, end_time, ip, confidence
    """
    page = int(request.args.get('page', 1))
    limit = int(request.args.get('limit', 10))
    offset = (page - 1) * limit

    # 筛选条件
    filters = []
    params = []

    victim_ip = request.args.get('ip')
    if victim_ip:
        filters.append("victim_ip = ?")
        params.append(victim_ip)

    confidence = request.args.get('confidence')
    if confidence:
        filters.append("confidence = ?")
        params.append(confidence)

    # 构造 SQL
    where_clause = "WHERE " + " AND ".join(filters) if filters else ""
    query = f"""
        SELECT id, scenario_id, victim_ip, attacker_ip, start_time, 
               confidence, attribution_type, attribution_name 
        FROM AttackReports 
        {where_clause}
        ORDER BY created_at DESC
        OFFSET ? ROWS FETCH NEXT ? ROWS ONLY
    """
    params.extend([offset, limit])

    # 统计总数 (用于前端分页)
    count_query = f"SELECT COUNT(*) FROM AttackReports {where_clause}"

    db = get_sql_conn()
    try:
        # 获取列表
        db.cursor.execute(query, params)
        columns = [column[0] for column in db.cursor.description]
        results = [dict(zip(columns, row)) for row in db.cursor.fetchall()]

        # 获取总数
        db.cursor.execute(count_query, params[:len(filters)])  # 只传筛选参数
        total = db.cursor.fetchval()

        return jsonify({
            "total": total,
            "page": page,
            "data": results
        })
    finally:
        db.close()


@app.route('/api/report/<scenario_id>', methods=['GET'])
def get_report_detail(scenario_id):
    """
    获取溯源报告详情，包含 C2 分析和画像
    """
    db = get_sql_conn()
    try:
        query = "SELECT report_json FROM AttackReports WHERE scenario_id = ?"
        db.cursor.execute(query, (scenario_id,))
        row = db.cursor.fetchone()

        if not row:
            return jsonify({"error": "Report not found"}), 404

        report_data = json.loads(row[0])

        # 【数据增强】: 在返回给前端前，处理 C2 信息和指纹
        report_data['c2_analysis'] = parse_c2_info(report_data.get('infrastructure', {}))
        report_data['attacker_fingerprint'] = generate_attacker_fingerprint(report_data)

        return jsonify(report_data)
    finally:
        db.close()


@app.route('/api/graph/<scenario_id>/summary', methods=['GET'])
def get_graph_summary(scenario_id):
    """
    【问题1回答】返回 ATT&CK 攻击链 (Vis.js 格式)
    """
    try:
        data = serializer.get_attack_chain_summary(scenario_id)
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/graph/<scenario_id>/topology', methods=['GET'])
def get_graph_topology(scenario_id):
    """
    【问题1回答】返回底层实体图 (Vis.js 格式)
    """
    try:
        data = serializer.get_scenario_topology(scenario_id)
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


pipeline_thread = None


@app.route('/api/system/status', methods=['GET'])
def get_system_status():
    """
    查询当前分析引擎是否在运行
    """
    global pipeline_thread
    is_running = pipeline_thread is not None and pipeline_thread.is_alive()
    return jsonify({
        "status": "running" if is_running else "stopped",
        "message": "系统正常运行中" if is_running else "分析引擎已待机"
    })


@app.route('/api/system/start', methods=['POST'])
def start_pipeline():
    """
    启动后台分析任务
    """
    global pipeline_thread

    # 1. 检查是否已经在运行
    if pipeline_thread is not None and pipeline_thread.is_alive():
        return jsonify({"status": "error", "message": "任务已经在运行中"}), 400

    # 2. 重置停止标志
    main_pipeline.STOP_FLAG = False

    # 3. 创建并启动线程
    # target 指向 main_pipeline.py 里的 pipeline_loop 函数
    pipeline_thread = threading.Thread(target=main_pipeline.pipeline_loop)
    pipeline_thread.daemon = True  # 设置为守护线程，主程序退出时它也会退出
    pipeline_thread.start()

    return jsonify({"status": "success", "message": "分析引擎已启动"})


@app.route('/api/system/stop', methods=['POST'])
def stop_pipeline():
    """
    停止后台分析任务
    """
    global pipeline_thread

    if pipeline_thread is None or not pipeline_thread.is_alive():
        return jsonify({"status": "warning", "message": "任务并未运行"}), 200

    # 设置标志位，线程会在下一次 sleep 唤醒时退出循环
    main_pipeline.STOP_FLAG = True

    return jsonify({"status": "success", "message": "正在停止分析引擎（请等待当前周期完成）"})

if __name__ == '__main__':
    app.run(debug=True, port=5000)