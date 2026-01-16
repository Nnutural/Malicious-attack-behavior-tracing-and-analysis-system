# -*- coding: utf-8 -*-
"""
HostGuard Linux Engine (Full Visibility Edition) - schema v2

从 Falco JSON line 生成与你的新接口对齐的 event dict（存入 HostBehaviors.result）：
- entities 新字段：hash/user/file_path/listen_ports
- network 字段：src_ip/src_port/dst_ip/dst_port/protocol
- registry 字段 Linux 先留空（除非后续接 auditd）
"""

import json
import time
import os
import socket
import datetime
import hashlib
import re
import threading
from typing import Dict, Optional, Callable

LOG_FILE_PATH = "/var/log/falco_events.json"


class EventType:
    PROCESS_CREATE = "process_create"
    FILE_CREATE = "file_create"
    FILE_MODIFY = "file_modify"
    FILE_DELETE = "file_delete"
    FILE_READ = "file_read"
    PROCESS_INJECTION = "process_injection"
    NETWORK_CONNECT = "network_connection"
    SYSTEM_CALL = "system_call"


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
        # 1. 优先尝试：UDP 探测 (保留原有逻辑，万一后续切换了网络模式也能用)
        try:
            # 如果你知道宿主机在 Host-Only 网络的 IP（例如 192.168.56.1），
            # 也可以把这里的 "8.8.8.8" 改成宿主机 IP，那样即使断网也能成功。
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            pass

        # 2. 兜底方案：使用 Shell 命令 hostname -I (适用于 Host-Only/断网环境)
        try:
            import subprocess
            # hostname -I 返回类似 "192.168.56.101 172.17.0.1 \n"
            cmd = ["hostname", "-I"]
            output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode().strip()
            # 分割并取第一个非 127 开头的 IP
            ips = output.split()
            for ip in ips:
                if ip and not ip.startswith("127."):
                    return ip
        except Exception:
            pass

        # 3. 实在获取不到，返回本地回环
        return "127.0.0.1"

    @staticmethod
    def get_timestamp() -> str:
        return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    @staticmethod
    def calculate_sha256(filepath: str) -> Optional[str]:
        if not filepath or not os.path.isfile(filepath):
            return None
        try:
            sha256 = hashlib.sha256()
            with open(filepath, "rb") as f:
                for block in iter(lambda: f.read(4096), b""):
                    sha256.update(block)
            return sha256.hexdigest()
        except Exception:
            return None

    @staticmethod
    def strip_sudo(proc_name: str, cmd_line: str) -> str:
        if proc_name == "sudo" and cmd_line:
            parts = cmd_line.split()
            for part in parts[1:]:
                if not part.startswith("-") and "=" not in part:
                    return os.path.basename(part)
        return proc_name


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


class HostBehaviorEngine:
    def __init__(self):
        self._dedup_cache = {}
        self._lock = threading.Lock()

    def _is_duplicate(self, alert: Dict) -> bool:
        sig = f"{alert['event_type']}:{alert['entities'].get('command_line','')}"
        now = time.time()
        with self._lock:
            last_time = self._dedup_cache.get(sig, 0)
            if now - last_time < 0.5:
                return True
            self._dedup_cache[sig] = now
            return False

    def analyze_event(self, line: str) -> Optional[Dict]:
        try:
            raw = json.loads(line)
            output = raw.get("output", "") or ""
            fields = raw.get("output_fields", {}) or {}
            rule = raw.get("rule", "") or ""

            cmd = str(fields.get("proc.cmdline", "") or "")
            proc = str(fields.get("proc.name", "") or "")

            pid = int(fields.get("proc.pid", 0) or 0)
            ppid = int(fields.get("proc.ppid", 0) or 0)

            if (not proc or proc == "unknown") and cmd:
                proc = cmd.split()[0]
            proc = ForensicsUtils.strip_sudo(proc, cmd)

            user = fields.get("user.name") or fields.get("user") or None
            fd_name = fields.get("fd.name") or None

            src_ip = fields.get("fd.sip") or fields.get("fd.cip") or None
            dst_ip = fields.get("fd.dip") or None
            src_port = _to_int_or_none(fields.get("fd.sport"))
            dst_port = _to_int_or_none(fields.get("fd.dport"))
            proto = fields.get("fd.l4proto") or None

            entities = {
                "process_name": proc,
                "pid": pid,
                "parent_process": "unknown",
                "parent_pid": ppid,
                "command_line": cmd,

                # 新增字段
                "hash": None,
                "user": user,
                "file_path": None,
                "listen_ports": [],

                # registry（Linux 暂不实现）
                "registry_key": None,
                "registry_value_name": None,
                "registry_value_data": None,

                # network
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "protocol": proto,
            }

            behavior_features = {
                "is_abnormal_parent": False,
                "has_memory_injection": False,
                "is_sensitive_path": False,  # 新增
                "is_suspicious_cmd": False,  # 新增
                "is_suspicious_extension": False  # 新增
            }

            # 1. 检测敏感路径 (对应 HB_005)
            if entities["file_path"] and (
                    "/etc/shadow" in entities["file_path"] or "/etc/passwd" in entities["file_path"]):
                behavior_features["is_sensitive_path"] = True

            # 2. 检测可疑命令 (对应 HB_006)
            if "chmod" in proc or "chmod" in cmd:
                # 简单判断：赋予执行权限
                if "+x" in cmd or "777" in cmd:
                    behavior_features["is_suspicious_cmd"] = True

            # 3. 检测可疑后缀 (对应 HB_004, 虽然攻击脚本暂未用到 Webshell，但建议加上)
            if entities["file_path"] and (
                    entities["file_path"].endswith(".php") or entities["file_path"].endswith(".jsp")):
                behavior_features["is_suspicious_extension"] = True

            alert = {
                "data_source": "host_behavior",
                "timestamp": ForensicsUtils.get_timestamp(),
                "host_ip": ForensicsUtils.get_host_ip(),
                "event_type": "unknown",
                "action": ActionType.UNKNOWN,
                "entities": entities,
                "behavior_features": behavior_features,
                "description": output,
            }

            lower_rule = rule.lower()
            lower_out = output.lower()



            # 1) 注入
            if "process_injection" in lower_rule or "ptrace" in lower_out:
                alert["event_type"] = EventType.PROCESS_INJECTION
                alert["action"] = ActionType.INJECTION
                alert["behavior_features"]["has_memory_injection"] = True

            # 2) 网络
            elif "network" in lower_rule or "network" in output or "connection" in lower_out:
                alert["event_type"] = EventType.NETWORK_CONNECT
                alert["action"] = ActionType.CONNECTION

                # 兜底从 cmd 抓 ip
                if not entities["dst_ip"]:
                    ip_match = re.search(r"(\d{1,3}(\.\d{1,3}){3})", cmd)
                    if ip_match:
                        entities["dst_ip"] = ip_match.group(1)

            # 3) 文件
            elif "file" in lower_rule:
                file_path = fd_name or (cmd.split()[-1] if cmd else None)
                entities["file_path"] = file_path

                if "creation" in lower_out or "create" in lower_rule:
                    alert["event_type"] = EventType.FILE_CREATE
                    alert["action"] = ActionType.MODIFICATION
                elif "delete" in lower_out or "remove" in lower_rule or "rm " in cmd:
                    alert["event_type"] = EventType.FILE_DELETE
                    alert["action"] = ActionType.DELETION
                elif "read" in lower_out or "access" in lower_rule:
                    alert["event_type"] = EventType.FILE_READ
                    alert["action"] = ActionType.ACCESS
                else:
                    alert["event_type"] = EventType.FILE_MODIFY
                    alert["action"] = ActionType.MODIFICATION

                entities["hash"] = ForensicsUtils.calculate_sha256(file_path) if file_path else None

            # 4) 兜底：进程启动
            else:
                alert["event_type"] = EventType.PROCESS_CREATE
                alert["action"] = ActionType.EXECUTION
                if "python" in cmd and ("sh" in cmd or "bash" in cmd):
                    alert["behavior_features"]["is_abnormal_parent"] = True

            if self._is_duplicate(alert):
                return None

            return alert
        except Exception:
            return None


def run_forever(
    *,
    on_event: Callable[[dict, str], None],
    stop_event: threading.Event,
    log_path: str = LOG_FILE_PATH,
) -> None:
    engine = HostBehaviorEngine()
    if not os.path.exists(log_path):
        open(log_path, "a").close()

    with open(log_path, "r", encoding="utf-8", errors="ignore") as f_in:
        f_in.seek(0, 2)
        while not stop_event.is_set():
            line = f_in.readline()
            if not line:
                time.sleep(0.1)
                continue

            event = engine.analyze_event(line)
            if event:
                try:
                    on_event(event, line)
                except Exception:
                    pass