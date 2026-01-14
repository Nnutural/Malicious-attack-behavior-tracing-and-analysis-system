import pyodbc
import json
import logging

#----------------------------------------------------------------------
# 实现数据库的连接
#----------------------------------------------------------------------

SQL_CONN_STR = (
    "DRIVER={ODBC Driver 17 for SQL Server};"
    "SERVER=10.21.211.11,1433;"  # 改成目标主机 IP 和端口
    "DATABASE=APT_Intelligence;"
    "UID=sa;"
    "PWD=000000;"
)

class SQLServerLoader:
    def __init__(self, server, user, password, database):
        conn_str = (
            f"DRIVER={{ODBC Driver 17 for SQL Server}};"
            f"SERVER={server};"
            f"DATABASE={database};"
            f"UID={user};"
            f"PWD={password};"
        )
        self.conn = pyodbc.connect(conn_str)
        self.cursor = self.conn.cursor()

    def fetch_new_data(self, table_name, last_id):
        data_list = []
        new_max_id = last_id

        try:
            query = f"SELECT id, result FROM {table_name} WHERE id > ? ORDER BY id ASC"
            self.cursor.execute(query, (last_id,))

            # 获取列名用于转字典
            columns = [column[0] for column in self.cursor.description]
            rows = self.cursor.fetchall()

            if rows:
                # 将 pyodbc 的 Row 对象转换为字典
                results = [dict(zip(columns, row)) for row in rows]

                # 剩下的逻辑和之前一样，但基于字典操作
                new_max_id = max(row['id'] for row in results)

                for row in results:
                    if row['result']:
                        try:
                            parsed = json.loads(row['result'])
                            if isinstance(parsed, list):
                                data_list.extend(parsed)
                            else:
                                data_list.append(parsed)
                        except json.JSONDecodeError:
                            pass

            return data_list, new_max_id

        except Exception as e:
            logging.error(f"Error fetching from {table_name}: {e}")
            return [], last_id

    def save_analysis_report(self, report):
        """
        将单条溯源报告存入 SQL Server
        :param report: APT_Analysis_Engine 生成的单个报告字典
        """
        try:
            # 提取关键字段用于索引和筛选
            scenario_id = report.get('scenario_id')
            victim_ip = report.get('victim_ip')
            # 尝试从 root_cause 或 infrastructure 中获取攻击者IP
            attacker_ip = "Unknown"
            if report.get('root_cause', {}).get('intruder_ip'):
                attacker_ip = report['root_cause']['intruder_ip']

            # 时间解析
            time_window = report.get('time_window', '').split(' to ')
            start_time = time_window[0] if len(time_window) > 0 else None
            end_time = time_window[1] if len(time_window) > 1 else None

            # 归因信息
            attribution = report.get('attribution', {})
            attr_type = attribution.get('type', 'Unknown')
            attr_name = "Unknown"
            if attr_type == "Known APT":
                attr_name = attribution.get('result', {}).get('best_match')
            else:
                # 如果是未知组织，尝试提取生成的 Profile ID (假设在 result 里或者单独生成)
                # 这里暂存类型名
                attr_name = "Uncategorized Cluster"

            json_str = json.dumps(report, ensure_ascii=False)

            query = """
                INSERT INTO AttackReports 
                (scenario_id, victim_ip, attacker_ip, start_time, end_time, confidence, attribution_type, attribution_name, report_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, GETDATE())
            """

            # 注意：confidence 需要你从报告里提取，这里假设默认为 'High' 或从 report 中获取
            confidence = "High"

            self.cursor.execute(query, (
            scenario_id, victim_ip, attacker_ip, start_time, end_time, confidence, attr_type, attr_name, json_str))
            self.conn.commit()
            logging.info(f"溯源报告 {scenario_id} 已保存至数据库")

        except Exception as e:
            logging.error(f"Save report failed: {e}")
            self.conn.rollback()