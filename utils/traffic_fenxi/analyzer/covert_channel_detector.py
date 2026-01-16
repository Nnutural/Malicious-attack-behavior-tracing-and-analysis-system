"""
隐蔽信道检测模块
识别 DNS 隧道、HTTP 隐蔽信道、ICMP 隧道等
"""
from __future__ import annotations

from typing import Any
from collections import defaultdict
import re
import base64
import math


class CovertChannelDetector:
    """隐蔽信道检测器"""

    def __init__(self):
        self.dns_stats: dict[str, dict[str, Any]] = defaultdict(
            lambda: {"query_count": 0, "query_lengths": [], "domains": set(), "subdomain_lengths": []}
        )
        self.http_stats: dict[str, dict[str, Any]] = defaultdict(lambda: {"request_count": 0, "uri_lengths": [], "header_count": 0})
        self.icmp_stats: dict[str, dict[str, Any]] = defaultdict(lambda: {"packet_count": 0, "payload_sizes": []})

    def detect(self, packet_data: dict[str, Any]) -> dict[str, Any]:
        result = {"is_covert_channel": False, "channel_type": None, "confidence": 0.0, "details": {}}

        protocol = packet_data.get("protocol", "")
        dst_port = packet_data.get("dst_port")
        entities = packet_data.get("entities", {}) or {}
        traffic_features = packet_data.get("traffic_features", {}) or {}

        # DNS 隧道
        if protocol == "UDP" and (dst_port == 53 or entities.get("domain")):
            dns_result = self._detect_dns_tunnel(packet_data, entities)
            if dns_result.get("is_covert"):
                result["is_covert_channel"] = True
                result["channel_type"] = "DNS Tunneling"
                result["confidence"] = float(dns_result.get("confidence") or 0.0)
                result["details"] = dns_result

        # HTTP 隐蔽信道（极简特征）
        if traffic_features.get("has_http") or protocol == "TCP":
            http_result = self._detect_http_covert(traffic_features)
            if http_result.get("is_covert"):
                result["is_covert_channel"] = True
                result["channel_type"] = "HTTP Covert Channel"
                result["confidence"] = max(result["confidence"], float(http_result.get("confidence") or 0.0))
                result["details"]["http"] = http_result

        # ICMP 隧道
        if protocol == "ICMP":
            icmp_result = self._detect_icmp_tunnel(packet_data)
            if icmp_result.get("is_covert"):
                result["is_covert_channel"] = True
                result["channel_type"] = "ICMP Tunneling"
                result["confidence"] = max(result["confidence"], float(icmp_result.get("confidence") or 0.0))
                result["details"]["icmp"] = icmp_result

        return result

    def _detect_dns_tunnel(self, packet_data: dict[str, Any], entities: dict) -> dict[str, Any]:
        domain = entities.get("domain")
        if not domain:
            return {"is_covert": False, "confidence": 0.0}

        src_ip = packet_data.get("src_ip")
        confidence = 0.0
        indicators: list[str] = []

        parts = str(domain).split(".")
        if len(parts) > 2:
            subdomain = parts[0]
            subdomain_len = len(subdomain)

            if src_ip:
                self.dns_stats[src_ip]["query_count"] += 1
                self.dns_stats[src_ip]["query_lengths"].append(len(domain))
                self.dns_stats[src_ip]["domains"].add(domain)
                self.dns_stats[src_ip]["subdomain_lengths"].append(subdomain_len)

            if subdomain_len > 50:
                confidence += 0.3
                indicators.append(f"子域名长度异常: {subdomain_len} 字符")

            if self._is_base64_like(subdomain):
                confidence += 0.4
                indicators.append("子域名包含 Base64 编码特征")

            if self._has_high_entropy(subdomain):
                confidence += 0.2
                indicators.append("子域���熵值高，疑似随机字符串")

            if src_ip:
                stats = self.dns_stats[src_ip]
                if stats["query_count"] > 100:
                    confidence += 0.1
                    indicators.append(f"DNS 查询频率异常: {stats['query_count']} 次")

        return {"is_covert": confidence > 0.5, "confidence": min(confidence, 1.0), "indicators": indicators, "domain": domain}

    def _detect_http_covert(self, traffic_features: dict) -> dict[str, Any]:
        confidence = 0.0
        indicators: list[str] = []
        http_method = traffic_features.get("http_method")
        if http_method and http_method not in ["GET", "POST", "PUT", "DELETE"]:
            confidence += 0.3
            indicators.append(f"异常的 HTTP 方法: {http_method}")
        return {"is_covert": confidence > 0.5, "confidence": min(confidence, 1.0), "indicators": indicators}

    def _detect_icmp_tunnel(self, packet_data: dict[str, Any]) -> dict[str, Any]:
        packet_len = int(packet_data.get("packet_length", 0) or 0)
        confidence = 0.0
        indicators: list[str] = []
        if packet_len > 1000:
            confidence += 0.6
            indicators.append(f"ICMP 数据包异常大: {packet_len} 字节")
        if packet_len > 500:
            confidence += 0.2
            indicators.append("ICMP 数据包大小异常")
        return {"is_covert": confidence > 0.5, "confidence": min(confidence, 1.0), "indicators": indicators, "packet_size": packet_len}

    def _is_base64_like(self, text: str) -> bool:
        if len(text) < 4:
            return False
        base64_pattern = re.compile(r"^[A-Za-z0-9+/=]+$")
        if not base64_pattern.match(text):
            return False
        if len(text) % 4 == 0 or "=" in text:
            try:
                base64.b64decode(text, validate=True)
                return True
            except Exception:
                pass
        return False

    def _has_high_entropy(self, text: str) -> bool:
        if len(text) < 4:
            return False
        char_freq = defaultdict(int)
        for char in text:
            char_freq[char] += 1
        entropy = 0.0
        length = len(text)
        for count in char_freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        unique_chars = len(set(text))
        if unique_chars <= 1:
            return False
        max_entropy = math.log2(unique_chars)
        normalized = entropy / max_entropy if max_entropy > 0 else 0
        return normalized > 0.7