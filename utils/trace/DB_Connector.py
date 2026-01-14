import pyodbc
import json
import logging

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


    def save_analysis_report(self, report_json):
        """
        将最终的溯源报告写回 SQL Server
        你需要先在 SQL Server 建一张表：AttackReports (id, report_json, created_at)
        """
        try:
            json_str = json.dumps(report_json, ensure_ascii=False)
            query = "INSERT INTO AttackReports (report_json, created_at) VALUES (%s, GETDATE())"
            self.cursor.execute(query, (json_str,))
            self.conn.commit()
            logging.info("溯源报告已保存至数据库")
        except Exception as e:
            logging.error(f"Save report failed: {e}")
            self.conn.rollback()

    def close(self):
        self.conn.close()