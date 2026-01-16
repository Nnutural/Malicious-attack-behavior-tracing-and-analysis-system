"""
网络会话重建模块
基于五元组（源IP、目标IP、源端口、目标端口、协议）重建网络会话
"""
from __future__ import annotations

from typing import Any
from collections import defaultdict


class SessionRebuilder:
    """网络会话重建器"""

    def __init__(self):
        # key: (src_ip, dst_ip, src_port, dst_port, protocol)
        self.sessions: dict[tuple, dict[str, Any]] = {}

    def add_packet(self, packet_data: dict[str, Any]):
        src_ip = packet_data.get("src_ip")
        dst_ip = packet_data.get("dst_ip")
        src_port = packet_data.get("src_port")
        dst_port = packet_data.get("dst_port")
        protocol = packet_data.get("protocol")

        if not src_ip or not dst_ip or not protocol:
            return

        session_key = (src_ip, dst_ip, src_port, dst_port, protocol)

        if session_key not in self.sessions:
            self.sessions[session_key] = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "packet_count": 0,
                "total_bytes": 0,
                "first_seen": packet_data.get("timestamp"),
                "last_seen": packet_data.get("timestamp"),
            }

        session = self.sessions[session_key]
        session["packet_count"] += 1
        session["total_bytes"] += int(packet_data.get("packet_length", 0) or 0)

        packet_time = packet_data.get("timestamp")
        if packet_time:
            if not session["first_seen"] or packet_time < session["first_seen"]:
                session["first_seen"] = packet_time
            if not session["last_seen"] or packet_time > session["last_seen"]:
                session["last_seen"] = packet_time

    def get_sessions(self) -> list[dict[str, Any]]:
        return list(self.sessions.values())

    def get_statistics(self) -> dict[str, Any]:
        total_sessions = len(self.sessions)
        total_packets = sum(int(s["packet_count"]) for s in self.sessions.values())
        total_bytes = sum(int(s["total_bytes"]) for s in self.sessions.values())

        protocol_stats = defaultdict(int)
        for session in self.sessions.values():
            protocol_stats[session["protocol"]] += 1

        return {
            "total_sessions": total_sessions,
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "protocol_distribution": dict(protocol_stats),
        }