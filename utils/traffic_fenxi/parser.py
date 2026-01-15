"""
PCAP 文件解析器
使用 scapy 解析 pcap/pcapng 文件，提取网络流量信息
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from scapy.all import rdpcap, IP, TCP, UDP, ICMP, DNS, Raw
from scapy.layers.inet6 import IPv6


class PcapParser:
    """PCAP 文件解析器"""

    def __init__(self, pcap_file: str):
        self.pcap_file = pcap_file
        self.packets = None

    def load(self) -> bool:
        try:
            self.packets = rdpcap(self.pcap_file)
            return True
        except Exception as e:
            print(f"加载 pcap 文件失败: {e}")
            return False

    def _determine_event_type(self, packet, protocol: str | None, has_dns: bool) -> str:
        if has_dns:
            return "dns_query"
        if protocol == "TCP":
            return "tcp_connection"
        if protocol == "UDP":
            return "dns_query" if has_dns else "tcp_connection"
        if protocol == "ICMP":
            return "icmp_tunnel_suspected"
        return "tcp_connection"

    def parse_packet(self, packet) -> dict[str, Any] | None:
        if not packet:
            return None

        timestamp = float(packet.time) if hasattr(packet, "time") else None
        if timestamp:
            dt = datetime.fromtimestamp(timestamp)
            timestamp_str = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        else:
            timestamp_str = None

        src_ip = None
        dst_ip = None
        protocol: str | None = None
        src_port = None
        dst_port = None

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            if TCP in packet:
                src_port = int(packet[TCP].sport)
                dst_port = int(packet[TCP].dport)
                protocol = "TCP"
            elif UDP in packet:
                src_port = int(packet[UDP].sport)
                dst_port = int(packet[UDP].dport)
                protocol = "UDP"
            elif ICMP in packet:
                protocol = "ICMP"
            else:
                protocol = "IPv4"

        elif IPv6 in packet:
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
            if TCP in packet:
                src_port = int(packet[TCP].sport)
                dst_port = int(packet[TCP].dport)
                protocol = "TCP"
            elif UDP in packet:
                src_port = int(packet[UDP].sport)
                dst_port = int(packet[UDP].dport)
                protocol = "UDP"
            else:
                protocol = "IPv6"

        if not src_ip or not dst_ip:
            return None

        packet_len = len(packet)

        entities: dict[str, Any] = {"payload_size": packet_len}
        traffic_features: dict[str, Any] = {}

        if DNS in packet:
            dns_layer = packet[DNS]
            if getattr(dns_layer, "qr", 1) == 0 and getattr(dns_layer, "qd", None):
                try:
                    domain = dns_layer.qd.qname.decode("utf-8").rstrip(".")
                    entities["domain"] = domain
                except Exception:
                    pass

                query_type_map = {1: "A", 2: "NS", 5: "CNAME", 15: "MX", 16: "TXT", 28: "AAAA"}
                qtype = getattr(dns_layer.qd, "qtype", None)
                if qtype is not None:
                    entities["query_type"] = query_type_map.get(int(qtype), f"TYPE{qtype}")

        if Raw in packet:
            try:
                raw_data = bytes(packet[Raw]).decode("utf-8", errors="ignore")
                if raw_data and ("HTTP" in raw_data or "GET" in raw_data or "POST" in raw_data):
                    traffic_features["has_http"] = True
                    lines = raw_data.split("\n")
                    if lines:
                        first = lines[0].strip()
                        if first.startswith("GET"):
                            traffic_features["http_method"] = "GET"
                        elif first.startswith("POST"):
                            traffic_features["http_method"] = "POST"
            except Exception:
                pass

        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol or "UNKNOWN",
            "timestamp": timestamp_str,
            "packet_length": packet_len,
            "event_type": self._determine_event_type(packet, protocol, DNS in packet),
            "entities": entities,
            "traffic_features": traffic_features,
        }

    def parse_all(self) -> list[dict[str, Any]]:
        if not self.packets:
            if not self.load():
                return []
        results = []
        for packet in self.packets:
            parsed = self.parse_packet(packet)
            if parsed:
                results.append(parsed)
        return results

    def get_raw_content(self) -> str:
        if not self.packets:
            if not self.load():
                return ""

        summary = {"file": self.pcap_file, "total_packets": len(self.packets), "sample_packets": []}
        for i, packet in enumerate(self.packets[:5]):
            summary["sample_packets"].append({"index": i, "summary": packet.summary()})
        return json.dumps(summary, ensure_ascii=False, indent=2)