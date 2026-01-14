from __future__ import annotations

from typing import Any


def get_mock_high_alerts() -> list[dict[str, Any]]:
    return [
        {
            "id": "ae-mock-001",
            "victim_ip": "10.21.226.213",
            "timestamp_start": "2026-01-13T05:59:08Z",
            "technique": "Command and Scripting Interpreter",
        },
        {
            "id": "ae-mock-002",
            "victim_ip": "10.21.226.213",
            "timestamp_start": "2026-01-13T06:13:24Z",
            "technique": "Exfiltration Over Alternative Protocol",
        },
    ]


def get_mock_report() -> list[dict[str, Any]]:
    report = [
        {
            "alert_id": "ae-mock-001",
            "trigger_technique": "T1059 - Command and Scripting Interpreter",
            "victim_ip": "10.21.226.213",
            "paths": {
                "process_tree": {
                    "root_process": "winword.exe",
                    "root_pid": 1200,
                    "root_cmd": r'"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" invoice.docm',
                    "user": "alice",
                    "execution_chain": ["winword.exe", "cmd.exe", "powershell.exe"],
                },
                "lateral_source": [
                    {
                        "source_ip": "45.33.22.11",
                        "compromised_user": "alice",
                        "logon_time": "2026-01-13T05:58:20Z",
                    }
                ],
                "exfiltration": [],
                "inferred_causality": [
                    {"dropper": "powershell.exe", "payload": "stage1.ps1", "execution": "powershell.exe", "lag": 2}
                ],
            },
            "attacker_profile": {
                "malware_hashes": [
                    "0f4d9c2b9b0b3a8f9d3c4b1a2f6d7e8c9a0b1c2d3e4f567890abcdef12345678"
                ],
                "c2_domains": ["evil-c2.example.com", "cdn-update.example.net"],
                "techniques": ["T1059", "T1071.004", "T1110"],
                "infrastructure_intelligence": [
                    {
                        "source": "VirusTotal",
                        "domain": "evil-c2.example.com",
                        "reputation_score": 6,
                        "registrar": "NameCheap, Inc.",
                        "creation_date": 1700000000,
                        "last_dns_records": ["45.33.22.11"],
                        "tags": ["c2", "dns", "apt"],
                        "whois_raw": "Mock WHOIS ...",
                        "categories": {"MockVendor": "malware"},
                    }
                ],
                "suspected_apt": [
                    {
                        "group": "APT28",
                        "similarity_score": 0.33,
                        "matched_techniques": ["T1110"],
                        "missing_techniques": ["T1048", "T1132", "T1059.001"],
                    }
                ],
            },
        },
        {
            "alert_id": "ae-mock-002",
            "trigger_technique": "T1048 - Exfiltration Over Alternative Protocol",
            "victim_ip": "10.21.226.213",
            "paths": {
                "process_tree": {
                    "root_process": "svchost.exe",
                    "root_pid": 888,
                    "root_cmd": r"svchost.exe -k netsvcs",
                    "user": "SYSTEM",
                    "execution_chain": ["svchost.exe", "rclone.exe"],
                },
                "lateral_source": [
                    {"source_ip": "10.21.226.50", "compromised_user": "administrator", "logon_time": "2026-01-13T06:10:10Z"}
                ],
                "exfiltration": [
                    {
                        "sensitive_file": r"C:\Users\alice\Documents\salary.xlsx",
                        "leaking_process": "rclone.exe",
                        "destination_ip": "45.33.22.11",
                    }
                ],
            },
            "attacker_profile": {
                "malware_hashes": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
                "c2_domains": ["dropbox-sync.example.org"],
                "techniques": ["T1048", "T1547.001", "T1005"],
                "infrastructure_intelligence": [
                    {
                        "source": "VirusTotal",
                        "domain": "dropbox-sync.example.org",
                        "reputation_score": 3,
                        "registrar": "MockRegistrar",
                        "creation_date": 1690000000,
                        "last_dns_records": ["45.33.22.11"],
                        "tags": ["exfil", "cloud"],
                        "whois_raw": "Mock WHOIS ...",
                        "categories": {"MockVendor": "suspicious"},
                    }
                ],
                "suspected_apt": [
                    {
                        "group": "Lazarus",
                        "similarity_score": 0.2,
                        "matched_techniques": ["T1078"],
                        "missing_techniques": ["T1059.001", "T1204", "T1083"],
                    }
                ],
            },
        },
    ]

    # 给每条 report 填充 vis_graph + timeline（前端直接用）
    for item in report:
        item["vis_graph"] = _build_vis_graph(item)
        item["timeline"] = _build_timeline(item)

    return report


def _build_vis_graph(item: dict[str, Any]) -> dict[str, Any]:
    victim_ip = item.get("victim_ip") or "unknown"
    alert_id = item.get("alert_id") or "ae"
    tech = item.get("trigger_technique") or ""

    nodes = []
    edges = []

    def add_node(_id: str, label: str, group: str, **extra):
        nodes.append({"id": _id, "label": label, "group": group, **extra})

    def add_edge(a: str, b: str, label: str):
        edges.append({"from": a, "to": b, "label": label, "arrows": "to"})

    add_node(alert_id, f"AttackEvent\n{alert_id}", "AttackEvent")
    add_node(f"ip:{victim_ip}", victim_ip, "VictimIP")
    add_edge(alert_id, f"ip:{victim_ip}", "TARGET")

    if tech:
        add_node(f"tech:{tech}", tech, "Technique")
        add_edge(alert_id, f"tech:{tech}", "IS_TYPE")

    pt = (item.get("paths") or {}).get("process_tree") or {}
    chain = pt.get("execution_chain") or []
    prev = None
    for idx, pname in enumerate(chain):
        pid = f"proc:{victim_ip}:{pname}:{idx}"
        add_node(pid, pname, "Process")
        if prev:
            add_edge(prev, pid, "Spawn")
        else:
            add_edge(alert_id, pid, "TRIGGER_CONTEXT")
        prev = pid

    # lateral
    for x in ((item.get("paths") or {}).get("lateral_source") or []):
        src = x.get("source_ip")
        user = x.get("compromised_user")
        if src:
            add_node(f"ip:{src}", src, "SourceIP")
            add_edge(f"ip:{src}", f"ip:{victim_ip}", "Logon_Source")
        if user:
            add_node(f"user:{victim_ip}:{user}", user, "User")
            add_edge(f"user:{victim_ip}:{user}", f"ip:{victim_ip}", "Logon")

    # exfil
    for x in ((item.get("paths") or {}).get("exfiltration") or []):
        f = x.get("sensitive_file")
        p = x.get("leaking_process")
        dst = x.get("destination_ip")
        if f:
            add_node(f"file:{victim_ip}:{f}", f, "File")
        if p:
            add_node(f"proc:{victim_ip}:{p}:exfil", p, "Process")
        if dst:
            add_node(f"ip:{dst}", dst, "ExternalIP")
        if p and f:
            add_edge(f"proc:{victim_ip}:{p}:exfil", f"file:{victim_ip}:{f}", "Read")
        if p and dst:
            add_edge(f"proc:{victim_ip}:{p}:exfil", f"ip:{dst}", "Connect")

    # domains
    for d in ((item.get("attacker_profile") or {}).get("c2_domains") or []):
        add_node(f"domain:{d}", d, "Domain")
        add_edge(alert_id, f"domain:{d}", "C2")

    return {"nodes": nodes, "edges": edges}


def _build_timeline(item: dict[str, Any]) -> list[dict[str, Any]]:
    victim_ip = item.get("victim_ip")
    alert_id = item.get("alert_id")
    tech = item.get("trigger_technique")

    timeline = []
    for x in ((item.get("paths") or {}).get("lateral_source") or []):
        timeline.append(
            {
                "time": x.get("logon_time"),
                "event_type": "user_logon",
                "source": "host_log",
                "summary": f"疑似入口登录：{x.get('source_ip')} -> {victim_ip} (user={x.get('compromised_user')})",
                "raw": x,
            }
        )
    timeline.append(
        {
            "time": "2026-01-13T05:59:08Z",
            "event_type": "attack_event_high",
            "source": "attack_map",
            "summary": f"High 告警触发：{tech} ({alert_id})",
            "raw": {"alert_id": alert_id, "technique": tech},
        }
    )
    for x in ((item.get("paths") or {}).get("exfiltration") or []):
        timeline.append(
            {
                "time": "2026-01-13T06:13:24Z",
                "event_type": "data_exfiltration",
                "source": "network_traffic",
                "summary": f"疑似外传：{x.get('sensitive_file')} -> {x.get('destination_ip')} (proc={x.get('leaking_process')})",
                "raw": x,
            }
        )
    timeline.sort(key=lambda e: e.get("time") or "")
    return timeline