# -*- coding: utf-8 -*-
"""
Windows 主机行为监控（Sysmon）：
- EvtSubscribe 订阅 Microsoft-Windows-Sysmon/Operational
- 将 Sysmon XML 解析为标准 event dict（host_behavior）
- run_forever: 持续监听并回调 on_event(event_dict, raw_xml)

输出 schema（与你的新接口对齐）：
{
  data_source, timestamp, host_ip, event_type, action,
  entities: {
    process_name,pid,parent_process,parent_pid,command_line,
    hash,user,file_path,listen_ports,
    registry_key,registry_value_name,registry_value_data,
    src_ip,src_port,dst_ip,dst_port,protocol
  },
  behavior_features: {is_abnormal_parent, has_memory_injection},
  description
}
"""

from __future__ import annotations

import datetime
import hashlib
import os
import re
import socket
import sys
import threading
import time
import xml.etree.ElementTree as ET
from typing import Callable, Dict, Optional

try:
    import win32evtlog  # type: ignore
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
    UNKNOWN = "unknown"


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
                # Sysmon UtcTime 常见：2026-01-13 12:34:56.123
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


def _to_int_or_none(value) -> int | None:
    try:
        if value is None:
            return None
        text = str(value).strip()
        if not text:
            return None
        return int(text)
    except Exception:
        return None


def _split_registry_target(target: str) -> tuple[str | None, str | None]:
    text = (target or "").strip()
    if not text:
        return None, None
    if "\\" not in text:
        return text, None
    parts = text.split("\\")
    if len(parts) <= 1:
        return text, None
    key = "\\".join(parts[:-1])
    value_name = parts[-1] or None
    return key or None, value_name


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

        entities = {
            "process_name": process_name,
            "pid": int(raw_data.get("ProcessId", 0) or 0),
            "parent_process": parent_name,
            "parent_pid": int(raw_data.get("ParentProcessId", 0) or 0),
            "command_line": raw_data.get("CommandLine", "") or "",

            # 新增字段（默认值）
            "hash": None,
            "user": raw_data.get("User", "") or raw_data.get("UserName", "") or None,
            "file_path": None,
            "listen_ports": [],

            # registry
            "registry_key": None,
            "registry_value_name": None,
            "registry_value_data": None,

            # network
            "src_ip": None,
            "src_port": None,
            "dst_ip": None,
            "dst_port": None,
            "protocol": None,
        }

        alert = {
            "data_source": "host_behavior",
            "timestamp": ForensicsUtils.get_timestamp_iso(raw_data.get("UtcTime")),
            "host_ip": ForensicsUtils.get_host_ip(),
            "event_type": "unknown",
            "action": ActionType.UNKNOWN,
            "entities": entities,
            "behavior_features": {"is_abnormal_parent": False, "has_memory_injection": False},
            "description": f"Sysmon Event {event_id}",
        }

        matched = False

        # Sysmon 1: Process Create
        if event_id == 1:
            alert["event_type"] = EventType.PROCESS_CREATE
            alert["action"] = ActionType.EXECUTION

            # hash：优先 Sysmon 提供的 SHA256
            hashes = raw_data.get("Hashes", "") or ""
            if "SHA256=" in hashes:
                try:
                    entities["hash"] = hashes.split("SHA256=")[1].split(",")[0]
                except Exception:
                    pass

            entities["file_path"] = image_path or None

            # 简单异常父子判定
            p_lower = parent_name.lower()
            c_lower = process_name.lower()
            if ("python" in p_lower or "word" in p_lower or "excel" in p_lower) and ("cmd" in c_lower or "powershell" in c_lower):
                alert["behavior_features"]["is_abnormal_parent"] = True
                alert["description"] = f"Suspicious spawn: {parent_name} -> {process_name}"

            matched = True

        # Sysmon 3: Network Connect
        elif event_id == 3:
            alert["event_type"] = EventType.NETWORK_CONNECT
            alert["action"] = ActionType.CONNECTION

            entities["src_ip"] = raw_data.get("SourceIp") or None
            entities["src_port"] = _to_int_or_none(raw_data.get("SourcePort"))
            entities["dst_ip"] = raw_data.get("DestinationIp") or None
            entities["dst_port"] = _to_int_or_none(raw_data.get("DestinationPort"))
            entities["protocol"] = raw_data.get("Protocol") or None

            alert["description"] = f"Network connection to {entities['dst_ip']}:{entities['dst_port']}"
            matched = True

        # Sysmon 11: File Create
        elif event_id == 11:
            target_file = raw_data.get("TargetFilename", "") or ""
            alert["event_type"] = EventType.FILE_CREATE
            alert["action"] = ActionType.MODIFICATION

            entities["file_path"] = target_file or None
            entities["hash"] = ForensicsUtils.calculate_sha256(target_file)

            alert["description"] = f"File created: {target_file}"
            matched = True

        # Sysmon 23: File Delete
        elif event_id == 23:
            target_file = raw_data.get("TargetFilename", "") or ""
            alert["event_type"] = EventType.FILE_DELETE
            alert["action"] = ActionType.DELETION

            entities["file_path"] = target_file or None
            alert["description"] = f"File deleted: {target_file}"
            matched = True

        # Sysmon 12/13/14: Registry Set
        elif event_id in [12, 13, 14]:
            alert["event_type"] = EventType.REGISTRY_SET
            alert["action"] = ActionType.MODIFICATION

            target_obj = raw_data.get("TargetObject", "") or ""
            details = raw_data.get("Details", "") or ""

            key, value_name = _split_registry_target(target_obj)
            entities["registry_key"] = key
            entities["registry_value_name"] = value_name
            entities["registry_value_data"] = details or None

            alert["description"] = f"Registry set: {target_obj}"
            matched = True

        # Sysmon 8: CreateRemoteThread (Injection)
        elif event_id == 8:
            alert["event_type"] = EventType.PROCESS_INJECTION
            alert["action"] = ActionType.INJECTION
            alert["behavior_features"]["has_memory_injection"] = True
            alert["description"] = "Process injection detected (Sysmon Event 8)"
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

    _ = win32evtlog.EvtSubscribe(
        channel,
        win32evtlog.EvtSubscribeToFutureEvents,
        None,
        on_event_callback,
        engine,
        None,
        None,
    )

    while not stop_event.is_set():
        time.sleep(0.5)