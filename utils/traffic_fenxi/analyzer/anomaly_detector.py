"""
异常协议行为建模模块
基于自定义规则检测异常协议行为
"""
from __future__ import annotations

from typing import Any
from collections import defaultdict


class AnomalyDetector:
    """异常协议行为检测器"""

    def __init__(self):
        self.rules = self._init_rules()
        self.ip_stats: dict[str, dict[str, Any]] = defaultdict(
            lambda: {
                "packet_count": 0,
                "bytes": 0,
                "ports": set(),
                "protocols": set(),
                "first_seen": None,
                "last_seen": None,
            }
        )

    def _init_rules(self) -> list[dict[str, Any]]:
        return [
            {
                "rule_id": "ANOMALY_001",
                "name": "异常端口扫描",
                "description": "检测短时间内访问大量不同端口的行为",
                "threshold": {"port_count": 10, "time_window": 60},
            },
            {
                "rule_id": "ANOMALY_002",
                "name": "异常协议使用",
                "description": "检测使用非标准端口的常见协议",
                "protocol_ports": {
                    "HTTP": [80, 8080, 8000],
                    "HTTPS": [443, 8443],
                    "SSH": [22],
                    "FTP": [21],
                    "DNS": [53],
                },
            },
            {
                "rule_id": "ANOMALY_003",
                "name": "异常流量大小",
                "description": "检测异常大的数据包或流量",
                "threshold": {"max_packet_size": 65535, "max_session_bytes": 100 * 1024 * 1024},
            },
            {
                "rule_id": "ANOMALY_004",
                "name": "异常协议组合",
                "description": "检测异常的协议组合模式（如 TCP+53）",
                "suspicious_patterns": [
                    {"protocol": "TCP", "port": 53},
                    {"protocol": "UDP", "port": 80},
                ],
            },
        ]

    def analyze_packet(self, packet_data: dict[str, Any]) -> list[dict[str, Any]]:
        anomalies: list[dict[str, Any]] = []

        src_ip = packet_data.get("src_ip")
        dst_port = packet_data.get("dst_port")
        protocol = packet_data.get("protocol")
        packet_len = int(packet_data.get("packet_length", 0) or 0)
        timestamp = packet_data.get("timestamp")

        if src_ip:
            self._update_ip_stats(src_ip, dst_port, protocol, packet_len, timestamp)

        for rule in self.rules:
            rule_id = rule["rule_id"]
            if rule_id == "ANOMALY_001":
                anomaly = self._detect_port_scan(src_ip, rule, timestamp)
                if anomaly:
                    anomalies.append(anomaly)
            elif rule_id == "ANOMALY_002":
                anomaly = self._detect_abnormal_protocol_port(protocol, dst_port, rule)
                if anomaly:
                    anomalies.append(anomaly)
            elif rule_id == "ANOMALY_003":
                anomaly = self._detect_abnormal_size(packet_len, rule)
                if anomaly:
                    anomalies.append(anomaly)
            elif rule_id == "ANOMALY_004":
                anomaly = self._detect_abnormal_protocol_combination(protocol, dst_port, rule)
                if anomaly:
                    anomalies.append(anomaly)

        return anomalies

    def _update_ip_stats(self, ip: str, port: int | None, protocol: str, bytes_count: int, timestamp: str | None):
        stats = self.ip_stats[ip]
        stats["packet_count"] += 1
        stats["bytes"] += bytes_count
        if port:
            stats["ports"].add(port)
        if protocol:
            stats["protocols"].add(protocol)
        if timestamp:
            if not stats["first_seen"]:
                stats["first_seen"] = timestamp
            stats["last_seen"] = timestamp

    def _detect_port_scan(self, ip: str | None, rule: dict, timestamp: str | None) -> dict[str, Any] | None:
        if not ip or ip not in self.ip_stats:
            return None
        stats = self.ip_stats[ip]
        port_count = len(stats["ports"])
        threshold = int(rule["threshold"]["port_count"])
        if port_count >= threshold:
            return {
                "rule_id": rule["rule_id"],
                "rule_name": rule["name"],
                "severity": "HIGH",
                "description": f"IP {ip} 在短时间内访问了 {port_count} 个不同端口（阈值: {threshold}）",
                "ip": ip,
                "port_count": port_count,
                "timestamp": timestamp,
            }
        return None

    def _detect_abnormal_protocol_port(self, protocol: str, port: int | None, rule: dict) -> dict[str, Any] | None:
        if not protocol or not port:
            return None
        protocol_ports = rule.get("protocol_ports") or {}
        for proto_name, standard_ports in protocol_ports.items():
            if protocol.upper() == proto_name.upper() and port not in standard_ports:
                return {
                    "rule_id": rule["rule_id"],
                    "rule_name": rule["name"],
                    "severity": "MEDIUM",
                    "description": f"检测到 {protocol} 协议使用非标准端口 {port}（标准端口: {standard_ports}）",
                    "protocol": protocol,
                    "port": port,
                    "standard_ports": standard_ports,
                }
        return None

    def _detect_abnormal_size(self, packet_len: int, rule: dict) -> dict[str, Any] | None:
        threshold = int(rule["threshold"]["max_packet_size"])
        if packet_len > threshold:
            return {
                "rule_id": rule["rule_id"],
                "rule_name": rule["name"],
                "severity": "MEDIUM",
                "description": f"检测到异常大的数据包: {packet_len} 字节（阈值: {threshold}）",
                "packet_size": packet_len,
                "threshold": threshold,
            }
        return None

    def _detect_abnormal_protocol_combination(self, protocol: str, port: int | None, rule: dict) -> dict[str, Any] | None:
        if not protocol or not port:
            return None
        for pattern in rule.get("suspicious_patterns") or []:
            if pattern.get("protocol") == protocol and pattern.get("port") == port:
                return {
                    "rule_id": rule["rule_id"],
                    "rule_name": rule["name"],
                    "severity": "MEDIUM",
                    "description": f"检测到异常的协议端口组合: {protocol} 协议使用端口 {port}",
                    "protocol": protocol,
                    "port": port,
                }
        return None