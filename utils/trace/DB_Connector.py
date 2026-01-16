import os
import pyodbc
import json
import logging
from config import Config

# 默认连接配置：改为 SecurityTraceDB（你要求的）
DEFAULT_SQL_SERVER = os.getenv("TRACE_SQL_HOST", "10.21.226.213,1433")
DEFAULT_SQL_USER = os.getenv("TRACE_SQL_USER", "sa")
DEFAULT_SQL_PASS = os.getenv("TRACE_SQL_PASS", "123123")
DEFAULT_SQL_DB = os.getenv("TRACE_SQL_DB", "SecurityTraceDB")


class SQLServerLoader:
    def __init__(self, server=None, user=None, password=None, database=None):
        server = server or DEFAULT_SQL_SERVER
        user = user or DEFAULT_SQL_USER
        password = password or DEFAULT_SQL_PASS
        database = database or DEFAULT_SQL_DB

        conn_str = (
            f"DRIVER={{ODBC Driver 17 for SQL Server}};"
            f"SERVER={server};"
            f"DATABASE={database};"
            f"UID={user};"
            f"PWD={password};"
            "TrustServerCertificate=yes;"
        )
        self.conn = pyodbc.connect(conn_str)
        self.cursor = self.conn.cursor()

    def close(self):
        try:
            self.cursor.close()
        except Exception:
            pass
        try:
            self.conn.close()
        except Exception:
            pass

    def fetch_new_data(self, table_name, last_id):
        data_list = []
        new_max_id = last_id

        try:
            query = f"SELECT id, result FROM {table_name} WHERE id > ? ORDER BY id ASC"
            self.cursor.execute(query, (last_id,))

            columns = [column[0] for column in self.cursor.description]
            rows = self.cursor.fetchall()

            if rows:
                results = [dict(zip(columns, row)) for row in rows]
                new_max_id = max(row["id"] for row in results)

                for row in results:
                    if row["result"]:
                        try:
                            parsed = json.loads(row["result"])
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
        将单条溯源报告存入 SQL Server dbo.AttackReports（SecurityTraceDB）
        """
        try:
            scenario_id = report.get("scenario_id")
            victim_ip = report.get("victim_ip")

            attacker_ip = "Unknown"
            rca = report.get("root_cause_analysis") or report.get("root_cause") or {}
            if isinstance(rca, dict) and rca.get("intruder_ip"):
                attacker_ip = rca.get("intruder_ip")

            time_window = str(report.get("time_window", "")).split(" to ")
            start_time = time_window[0] if len(time_window) > 0 else None
            end_time = time_window[1] if len(time_window) > 1 else None

            attribution = report.get("attribution", {}) or {}
            attr_type = attribution.get("type", "Unknown")
            if attr_type == "Known APT":
                attr_name = (attribution.get("result") or {}).get("best_match") or "Unknown"
            else:
                attr_name = "Uncategorized Cluster"

            json_str = json.dumps(report, ensure_ascii=False)

            confidence = report.get("confidence") or "High"

            query = """
                INSERT INTO dbo.AttackReports 
                (scenario_id, victim_ip, attacker_ip, start_time, end_time, confidence,
                 attribution_type, attribution_name, report_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, GETDATE())
            """
            self.cursor.execute(
                query,
                (scenario_id, victim_ip, attacker_ip, start_time, end_time, confidence, attr_type, attr_name, json_str),
            )
            self.conn.commit()
            logging.info(f"溯源报告 {scenario_id} 已保存至 SecurityTraceDB.dbo.AttackReports")

        except Exception as e:
            logging.error(f"Save report failed: {e}")
            try:
                self.conn.rollback()
            except Exception:
                pass