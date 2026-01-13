# -*- coding: utf-8 -*-
"""
Windows 主机行为监控（Sysmon）：
- EvtSubscribe 订阅 Microsoft-Windows-Sysmon/Operational
- 将 Sysmon XML 解析为标准 event dict（host_behavior）
- run_forever: 持续监听并回调 on_event(event_dict, raw_xml)

注意：本文件不再写 host_data.json（路线 A：直接回调入库）
"""

from __future__ import annotations

import os
import re
import sys
import time
import socket
import datetime
import hashlib
import threading
import xml.etree.ElementTree as ET
from typing import Dict, Optional, Callable

try:
    import win32evtlog
except ImportError:
    print("[!] Fatal Error: 'pywin32' library not found.")
    sys.exit(1)

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"


class EventType:
    PROCESS_CREATE = "process_create"
    FILE_CREATE = "file_create"
    FILE_MODIFY = "file_modify"
    FILE_DELETE = "file_delete"
    FILE_READ = "file_read"
    REGISTRY_SET = "registry_set_value"
    PROCESS_INJECTION = "process_injection"
    NETWORK_CONNECT = "network_connection"


class ActionType:
    EXECUTION = "execution"
    MODIFICATION = "modification"
    DELETION = "deletion"
    ACCESS = "access"
    CONNECTION = "connection"
    INJECTION = "injection"


class ForensicsUtils:
    @staticmethod
    def get_host_ip() -> str:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"

    @staticmethod
    def get_timestamp_iso(raw_time_str=None) -> str:
        if raw_time_str:
            try:
                return raw_time_str.replace(" ", "T") + "Z"
            except Exception:
                pass
        return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    @staticmethod
    def calculate_sha256(filepath: str) -> Optional[str]:
        if not filepath or not os.path.exists(filepath):
            return None
        if not os.path.isfile(filepath):
            return None
        try:
            sha256 = hashlib.sha256()
            with open(filepath, "rb") as f:
                for block in iter(lambda: f.read(4096), b""):
                    sha256.update(block)
            return sha256.hexdigest()
        except Exception:
            return None


class WindowsBehaviorEngine:
    def __init__(self, *, on_event: Callable[[dict, str], None]):
        self.on_event = on_event
        self.ns_pattern = re.compile(r" xmlns=['\"][^'\"]+['\"]")

    def _parse_xml_event(self, xml_content: str) -> Dict:
        data: Dict = {}
        try:
            xml_content = self.ns_pattern.sub("", xml_content, count=1)
            root = ET.fromstring(xml_content)

            sys_node = root.find("System")
            if sys_node is not None:
                eid = sys_node.find("EventID")
                if eid is not None and eid.text:
                    data["EventID"] = int(eid.text)

            for item in root.findall(".//EventData/Data"):
                name = item.attrib.get("Name")
                text = item.text
                if name:
                    data[name] = text if text else ""

            # ComputerName（用于 host_name 也可用）
            if sys_node is not None:
                comp = sys_node.find("Computer")
                if comp is not None and comp.text:
                    data["_Computer"] = comp.text.strip()

        except Exception:
            pass
        return data

    def process_alert(self, raw_data: Dict, raw_xml: str) -> None:
        event_id = raw_data.get("EventID")
        if not event_id:
            return

        image_path = raw_data.get("Image", "") or ""
        process_name = os.path.basename(image_path)
        parent_path = raw_data.get("ParentImage", "") or ""
        parent_name = os.path.basename(parent_path)

        alert = {
            "data_source": "host_behavior",
            "timestamp": ForensicsUtils.get_timestamp_iso(raw_data.get("UtcTime")),
            "host_ip": ForensicsUtils.get_host_ip(),
            "event_type": "unknown",
            "action": "unknown",
            "entities": {
                "process_name": process_name,
                "pid": int(raw_data.get("ProcessId", 0) or 0),
                "parent_process": parent_name,
                "parent_pid": int(raw_data.get("ParentProcessId", 0) or 0),
                "command_line": raw_data.get("CommandLine", "") or "",
                "file_hash": None,
                "target_file": None,
                "target_ip": None,
                "registry_key": None,
                "registry_value_name": None,
                "registry_value_data": None,
            },
            "behavior_features": {"is_abnormal_parent": False, "has_memory_injection": False},
            "description": f"Sysmon Event {event_id}",
        }

        matched = False

        if event_id == 1:
            alert["event_type"] = EventType.PROCESS_CREATE
            alert["action"] = ActionType.EXECUTION

            hashes = raw_data.get("Hashes", "") or ""
            if "SHA256=" in hashes:
                try:
                    alert["entities"]["file_hash"] = hashes.split("SHA256=")[1].split(",")[0]
                except Exception:
                    pass

            p_lower = parent_name.lower()
            c_lower = process_name.lower()
            if ("python" in p_lower or "word" in p_lower) and ("cmd" in c_lower or "powershell" in c_lower):
                alert["behavior_features"]["is_abnormal_parent"] = True
                alert["description"] = f"Suspicious spawn: {parent_name} -> {process_name}"

            matched = True

        elif event_id == 3:
            alert["event_type"] = EventType.NETWORK_CONNECT
            alert["action"] = ActionType.CONNECTION
            alert["entities"]["target_ip"] = raw_data.get("DestinationIp")
            alert["description"] = f"Network connection to {alert['entities']['target_ip']}"
            matched = True

        elif event_id == 11:
            target_file = raw_data.get("TargetFilename", "") or ""
            alert["event_type"] = EventType.FILE_CREATE
            alert["action"] = ActionType.MODIFICATION
            alert["entities"]["target_file"] = target_file
            alert["entities"]["file_hash"] = ForensicsUtils.calculate_sha256(target_file)
            alert["description"] = f"File created: {target_file}"
            matched = True

        elif event_id in [12, 13, 14]:
            alert["event_type"] = EventType.REGISTRY_SET
            alert["action"] = ActionType.MODIFICATION
            alert["entities"]["registry_key"] = raw_data.get("TargetObject", "") or ""
            details = raw_data.get("Details", "") or ""
            if details:
                alert["entities"]["registry_value_data"] = details
            matched = True

        elif event_id == 8:
            alert["event_type"] = EventType.PROCESS_INJECTION
            alert["action"] = ActionType.INJECTION
            alert["behavior_features"]["has_memory_injection"] = True
            matched = True

        elif event_id == 23:
            alert["event_type"] = EventType.FILE_DELETE
            alert["action"] = ActionType.DELETION
            alert["entities"]["target_file"] = raw_data.get("TargetFilename")
            matched = True

        if matched:
            try:
                self.on_event(alert, raw_xml)
            except Exception:
                pass


def run_forever(
    *,
    on_event: Callable[[dict, str], None],
    stop_event: threading.Event,
    channel: str = SYSMON_CHANNEL,
) -> None:
    engine = WindowsBehaviorEngine(on_event=on_event)

    def on_event_callback(action, context, event_handle):
        if action == win32evtlog.EvtSubscribeActionDeliver:
            try:
                xml_content = win32evtlog.EvtRender(event_handle, win32evtlog.EvtRenderEventXml)
                raw_data = context._parse_xml_event(xml_content)
                context.process_alert(raw_data, xml_content)
            except Exception:
                pass

    subscription = win32evtlog.EvtSubscribe(
        channel,
        win32evtlog.EvtSubscribeToFutureEvents,
        None,
        on_event_callback,
        engine,
        None,
        None,
    )

    # 保活，直到 stop_event 被 set
    while not stop_event.is_set():
        time.sleep(0.5)