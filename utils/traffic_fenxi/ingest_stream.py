from __future__ import annotations

import json
import logging
import queue
import time
from dataclasses import dataclass
from typing import Any

import pyodbc

from config import Config
from utils.traffic_fenxi.analyzer.session_rebuild import SessionRebuilder
from utils.traffic_fenxi.analyzer.anomaly_detector import AnomalyDetector
from utils.traffic_fenxi.analyzer.covert_channel_detector import CovertChannelDetector
from utils.traffic_fenxi.storage_sqlserver import generate_event_hash

logger = logging.getLogger(__name__)


@dataclass
class _Stats:
    inserted: int = 0
    skipped: int = 0
    errors: int = 0


class NetworkTrafficStreamIngestor:
    """
    在线流式入库器：
    - 从队列取解析后的 packet_data
    - 可选做 analysis
    - 拼成 result_json
    - 生成 event_hash 去重
    - 批量 executemany 写入 dbo.NetworkTraffic
    - 每 flush_interval_sec commit 一次
    """

    def __init__(
        self,
        *,
        conn_str: str | None = None,
        enable_analysis: bool = True,
        flush_interval_sec: float = 1.0,
        raw_content: str = "",
        host_name: str | None = None,
        batch_max: int = 2000,
    ):
        self.conn_str = conn_str or Config.SQL_CONN_STR
        self.enable_analysis = bool(enable_analysis)
        self.flush_interval_sec = float(flush_interval_sec)
        self.raw_content = raw_content
        self.host_name = host_name
        self.batch_max = int(batch_max)

        self.session_rebuilder = SessionRebuilder()
        self.anomaly_detector = AnomalyDetector()
        self.covert_detector = CovertChannelDetector()

        self.stats = _Stats()

    def get_stats(self) -> dict[str, int]:
        return {"inserted": self.stats.inserted, "skipped": self.stats.skipped, "errors": self.stats.errors}

    def _build_result_dict(self, packet_data: dict[str, Any]) -> dict[str, Any]:
        anomalies: list[dict[str, Any]] = []
        covert_result: dict[str, Any] = {}

        if self.enable_analysis:
            # 会话重建（目前用于内部统计/后续扩展，不写入单条事件）
            self.session_rebuilder.add_packet(packet_data)

            # 异常检测
            anomalies = self.anomaly_detector.analyze_packet(packet_data) or []
            if anomalies:
                packet_data["anomalies"] = anomalies
                # [新增修复]：如果检测到端口扫描异常，强制修改 event_type 以匹配 YAML 规则
                for anomaly in anomalies:
                    if anomaly.get("rule_id") == "ANOMALY_001":  # 对应 Port Scan
                        packet_data["event_type"] = "port_scan"
                        break

            # 隐蔽信道检测
            covert_result = self.covert_detector.detect(packet_data) or {}
            if covert_result.get("is_covert_channel"):
                packet_data.setdefault("traffic_features", {})
                packet_data["traffic_features"]["is_covert_channel"] = True
                packet_data["traffic_features"]["channel_type"] = covert_result.get("channel_type")
                packet_data["traffic_features"]["covert_confidence"] = covert_result.get("confidence")

                channel_type = covert_result.get("channel_type")
                if channel_type == "DNS Tunneling":
                    packet_data["event_type"] = "dns_tunnel_suspected"
                elif channel_type == "HTTP Covert Channel":
                    packet_data["event_type"] = "http_tunnel_suspected"
                elif channel_type == "ICMP Tunneling":
                    packet_data["event_type"] = "icmp_tunnel_suspected"

        result_dict: dict[str, Any] = {
            "data_source": "network_traffic",
            "timestamp": packet_data.get("timestamp"),
            "src_ip": packet_data.get("src_ip"),
            "dst_ip": packet_data.get("dst_ip"),
            "src_port": packet_data.get("src_port"),
            "dst_port": packet_data.get("dst_port"),
            "protocol": packet_data.get("protocol"),
            "event_type": packet_data.get("event_type", "tcp_connection"),
            "entities": packet_data.get("entities", {}) or {},
            "traffic_features": packet_data.get("traffic_features", {}) or {},
            "description": "",
        }

        # === 新增：结构化检测结果写入 result_dict（用于详情页展示证据） ===
        if self.enable_analysis:
            detections: dict[str, Any] = {}
            if anomalies:
                detections["anomalies"] = anomalies
            if covert_result:
                # covert_result 内部已包含 details/indicators 等
                detections["covert_channel"] = covert_result
            if detections:
                result_dict["detections"] = detections

        # description（人类可读摘要）
        parts: list[str] = []
        tf = result_dict["traffic_features"] or {}
        if tf.get("is_covert_channel"):
            ct = tf.get("channel_type", "")
            if ct == "DNS Tunneling":
                parts.append("Suspected DNS tunneling traffic")
            elif ct == "HTTP Covert Channel":
                parts.append("Suspected HTTP covert channel")
            elif ct == "ICMP Tunneling":
                parts.append("Suspected ICMP tunneling")

        for a in anomalies:
            d = a.get("description")
            if d:
                parts.append(d)

        if parts:
            result_dict["description"] = ". ".join(parts)

        return result_dict

    def _insert_batch(self, conn: pyodbc.Connection, batch: list[tuple[str, str, str | None, str | None]]):
        """
        batch: [(result_json, content, event_hash, host_name), ...]
        """
        if not batch:
            return
        sql = """
        INSERT INTO dbo.NetworkTraffic (result, content, event_hash, host_name)
        VALUES (?, ?, ?, ?)
        """
        cur = conn.cursor()
        cur.fast_executemany = True
        try:
            cur.executemany(sql, batch)
            conn.commit()
            self.stats.inserted += len(batch)
        except Exception:
            # 批量里可能存在重复 hash；为了演示稳定：逐条插入做去重
            conn.rollback()
            for item in batch:
                try:
                    cur.execute(sql, item)
                    conn.commit()
                    self.stats.inserted += 1
                except Exception:
                    # 大概率是唯一索引冲突
                    self.stats.skipped += 1

    def flush_queue(self, q: "queue.Queue[dict[str, Any]]"):
        try:
            conn = pyodbc.connect(self.conn_str)
        except Exception:
            logger.exception("DB connect failed in flush_queue")
            return

        batch: list[tuple[str, str, str | None, str | None]] = []
        try:
            while True:
                try:
                    pkt = q.get_nowait()
                except queue.Empty:
                    break

                try:
                    result_dict = self._build_result_dict(pkt)
                    event_hash = generate_event_hash(result_dict)
                    result_json = json.dumps(result_dict, ensure_ascii=False)
                    batch.append((result_json, self.raw_content, event_hash, self.host_name))
                except Exception:
                    self.stats.errors += 1
                    logger.exception("Failed to build packet during flush")

                if len(batch) >= self.batch_max:
                    self._insert_batch(conn, batch)
                    batch.clear()

            if batch:
                self._insert_batch(conn, batch)
        finally:
            conn.close()

    def run_writer_loop(self, q: "queue.Queue[dict[str, Any]]", stop_event):
        conn = pyodbc.connect(self.conn_str)
        batch: list[tuple[str, str, str | None, str | None]] = []
        last_flush = time.time()

        try:
            while not stop_event.is_set():
                timeout = max(0.05, self.flush_interval_sec / 10.0)
                try:
                    pkt = q.get(timeout=timeout)
                    result_dict = self._build_result_dict(pkt)
                    event_hash = generate_event_hash(result_dict)
                    result_json = json.dumps(result_dict, ensure_ascii=False)
                    batch.append((result_json, self.raw_content, event_hash, self.host_name))
                except queue.Empty:
                    pass
                except Exception:
                    self.stats.errors += 1
                    logger.exception("Failed to build packet")

                now = time.time()
                if batch and (len(batch) >= self.batch_max or (now - last_flush) >= self.flush_interval_sec):
                    try:
                        self._insert_batch(conn, batch)
                    except Exception:
                        self.stats.errors += len(batch)
                        logger.exception("DB insert failed")
                    finally:
                        batch.clear()
                        last_flush = now

            if batch:
                self._insert_batch(conn, batch)
        finally:
            conn.close()