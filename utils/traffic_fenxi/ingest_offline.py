"""
离线导入：parsed_packets -> result_dict -> DB（支持去重 event_hash + host_name）
"""
from __future__ import annotations

from typing import Any

from utils.traffic_fenxi.analyzer.session_rebuild import SessionRebuilder
from utils.traffic_fenxi.analyzer.anomaly_detector import AnomalyDetector
from utils.traffic_fenxi.analyzer.covert_channel_detector import CovertChannelDetector
from utils.traffic_fenxi.storage_sqlserver import insert_networktraffic_from_dict


def build_result_dict(packet_data: dict[str, Any]) -> dict[str, Any]:
    return {
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
        "description": packet_data.get("description", "") or "",
    }


def ingest_pcap_to_database(
    *,
    parsed_packets: list[dict[str, Any]],
    raw_content: str,
    conn_str: str | None = None,
    enable_analysis: bool = True,
    host_name: str | None = None,
) -> dict[str, Any]:
    inserted = 0
    skipped = 0
    errors = 0

    session_rebuilder = SessionRebuilder()
    anomaly_detector = AnomalyDetector()
    covert_detector = CovertChannelDetector()

    for packet_data in parsed_packets:
        try:
            if enable_analysis:
                session_rebuilder.add_packet(packet_data)

                anomalies = anomaly_detector.analyze_packet(packet_data)
                if anomalies:
                    packet_data["anomalies"] = anomalies

                covert_result = covert_detector.detect(packet_data)
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

                # description
                parts: list[str] = []
                tf = packet_data.get("traffic_features") or {}
                if tf.get("is_covert_channel"):
                    ct = tf.get("channel_type") or ""
                    if ct == "DNS Tunneling":
                        parts.append("Suspected DNS tunneling traffic")
                    elif ct == "HTTP Covert Channel":
                        parts.append("Suspected HTTP covert channel")
                    elif ct == "ICMP Tunneling":
                        parts.append("Suspected ICMP tunneling")
                for a in packet_data.get("anomalies") or []:
                    d = a.get("description")
                    if d:
                        parts.append(d)
                if parts:
                    packet_data["description"] = ". ".join(parts)

            result_dict = build_result_dict(packet_data)

            r = insert_networktraffic_from_dict(
                result_dict=result_dict,
                content=raw_content,
                host_name=host_name,
                conn_str=conn_str,
            )
            inserted += int(r["inserted"])
            skipped += int(r["skipped"])
            errors += int(r["errors"])

        except Exception:
            errors += 1

    analysis_results = {}
    if enable_analysis:
        sessions = session_rebuilder.get_sessions()
        analysis_results = {
            "sessions": {"total": len(sessions), "statistics": session_rebuilder.get_statistics()},
            "anomalies_detected": sum(1 for p in parsed_packets if "anomalies" in p),
            "covert_channels_detected": sum(1 for p in parsed_packets if p.get("traffic_features", {}).get("is_covert_channel", False)),
        }

    return {
        "inserted": inserted,
        "skipped": skipped,
        "errors": errors,
        "total_packets": len(parsed_packets),
        "analysis": analysis_results,
    }