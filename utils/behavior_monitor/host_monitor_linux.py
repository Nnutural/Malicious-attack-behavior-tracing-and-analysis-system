# -*- coding: utf-8 -*-
"""
Linux 主机行为监控：
- 读取 Falco JSON 日志（默认 /var/log/falco_events.json）
- analyze_event: 将一行 falco JSON 转为标准 event dict（host_behavior）
- run_forever: tail-f 监听，解析出 event 后回调 on_event(event, raw_line)

改进：
- 新增 read_last_lines 参数：启动时先回放最后 N 行（默认 200），避免“启动后一直等不到新行”。
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
    PROCESS_INJECTION = "process_injection"
    FILE_CREATE = "file_create"
    FILE_MODIFY = "file_modify"
    FILE_DELETE = "file_delete"
    FILE_READ = "file_read"
    NETWORK_CONNECT = "network_connection"
    PROCESS_CREATE = "process_create"
    REGISTRY_SET = "registry_set_value"


class ActionType:
    INJECTION = "injection"
    MODIFICATION = "modification"
    DELETION = "deletion"
    ACCESS = "access"
    CONNECTION = "connection"
    EXECUTION = "execution"


class ForensicsUtils:
    @staticmethod
    def get_host_ip() -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    @staticmethod
    def get_timestamp() -> str:
        return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    @staticmethod
    def calculate_sha256(filepath: str) -> str:
        if not filepath or not os.path.exists(filepath):
            return "unknown_or_deleted"
        if not os.path.isfile(filepath):
            return "not_a_regular_file"
        try:
            sha256_hash = hashlib.sha256()
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception:
            return "access_denied"

    @staticmethod
    def strip_sudo(proc_name: str, cmd_line: str) -> str:
        if proc_name == "sudo" and cmd_line:
            parts = cmd_line.split()
            for part in parts[1:]:
                if not part.startswith("-") and "=" not in part:
                    return os.path.basename(part)
        return proc_name


class HostBehaviorEngine:
    def __init__(self):
        self._dedup_cache = {}
        self._lock = threading.Lock()

    def _is_duplicate(self, alert: Dict) -> bool:
        sig = f"{alert['event_type']}:{alert['entities'].get('command_line','')}"
        now = time.time()
        with self._lock:
            last_time = self._dedup_cache.get(sig, 0)
            if now - last_time < 1.5:
                return True
            self._dedup_cache[sig] = now
            return False

    def analyze_event(self, line: str) -> Optional[Dict]:
        try:
            raw = json.loads(line)
            output = raw.get("output", "")
            fields = raw.get("output_fields", {}) or {}

            cmd = str(fields.get("proc.cmdline", "") or "")
            proc = str(fields.get("proc.name", "") or "")

            pid = int(fields.get("proc.pid", 0) or 0)
            ppid = int(fields.get("proc.ppid", 0) or 0)

            if (not proc or proc == "unknown") and cmd:
                proc = cmd.split()[0]
            proc = ForensicsUtils.strip_sudo(proc, cmd)

            alert = {
                "data_source": "host_behavior",
                "timestamp": ForensicsUtils.get_timestamp(),
                "host_ip": ForensicsUtils.get_host_ip(),
                "event_type": "unknown",
                "action": "unknown",
                "entities": {
                    "process_name": proc,
                    "pid": pid,
                    "parent_process": "unknown",
                    "parent_pid": ppid,
                    "command_line": cmd,
                    "registry_key": None,
                    "registry_value_name": None,
                    "registry_value_data": None,
                    "file_hash": None,
                    "target_file": None,
                    "target_ip": None,
                },
                "behavior_features": {"is_abnormal_parent": False, "has_memory_injection": False},
                "description": output,
            }

            target_file = ""

            if "PTRACE" in output or "strace" in cmd:
                alert["event_type"] = EventType.PROCESS_INJECTION
                alert["action"] = ActionType.INJECTION
                alert["behavior_features"]["has_memory_injection"] = True

            elif "Network" in output or any(x in cmd for x in ["nc ", "ncat ", "curl ", "wget "]):
                alert["event_type"] = EventType.NETWORK_CONNECT
                alert["action"] = ActionType.CONNECTION
                ip_match = re.search(r"(\d{1,3}(\.\d{1,3}){3})", cmd)
                if ip_match:
                    alert["entities"]["target_ip"] = ip_match.group(1)

            elif "File deletion" in output or "rm " in cmd:
                alert["event_type"] = EventType.FILE_DELETE
                alert["action"] = ActionType.DELETION
                alert["entities"]["target_file"] = cmd.split()[-1] if cmd else None

            elif "File creation" in output or "touch " in cmd:
                alert["event_type"] = EventType.FILE_CREATE
                alert["action"] = ActionType.MODIFICATION
                target_file = cmd.split()[-1] if cmd else ""
                alert["entities"]["target_file"] = target_file or None
                alert["entities"]["file_hash"] = ForensicsUtils.calculate_sha256(target_file)

            elif "File modification" in output or "chmod" in cmd or ">>" in cmd or " tee " in cmd or " > " in cmd:
                alert["event_type"] = EventType.FILE_MODIFY
                alert["action"] = ActionType.MODIFICATION
                if ">>" in cmd:
                    target_file = cmd.split(">>")[1].strip()
                elif ">" in cmd:
                    target_file = cmd.split(">")[1].strip()
                elif "chmod" in cmd:
                    target_file = cmd.split()[-1]
                alert["entities"]["target_file"] = target_file or None
                alert["entities"]["file_hash"] = ForensicsUtils.calculate_sha256(target_file)

            elif "Sensitive" in output or "shadow" in cmd or "unix_chkpwd" in proc:
                alert["event_type"] = EventType.FILE_READ
                alert["action"] = ActionType.ACCESS
                alert["entities"]["target_file"] = "/etc/shadow"

            elif "Python" in output or "Abnormal shell" in output:
                alert["event_type"] = EventType.PROCESS_CREATE
                alert["action"] = ActionType.EXECUTION
                alert["behavior_features"]["is_abnormal_parent"] = True
                exe_path = cmd.split()[0] if cmd else ""
                if exe_path and os.path.exists(exe_path):
                    alert["entities"]["file_hash"] = ForensicsUtils.calculate_sha256(exe_path)

            elif "Registry" in output:
                alert["event_type"] = EventType.REGISTRY_SET
                alert["action"] = ActionType.MODIFICATION
                alert["entities"]["registry_key"] = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\EvilExe"
                alert["entities"]["registry_value_name"] = "EvilExe"
                alert["entities"]["registry_value_data"] = r"C:\Windows\Temp\trojan.exe"

            else:
                return None

            if self._is_duplicate(alert):
                return None

            return alert
        except Exception:
            return None


def _read_last_lines(path: str, n: int) -> list[str]:
    if n <= 0:
        return []
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            block = 4096
            data = b""
            while size > 0 and data.count(b"\n") <= n:
                step = block if size >= block else size
                f.seek(-step, os.SEEK_CUR)
                data = f.read(step) + data
                f.seek(-step, os.SEEK_CUR)
                size -= step
        lines = data.splitlines()[-n:]
        return [ln.decode("utf-8", errors="ignore") for ln in lines]
    except Exception:
        return []


def run_forever(
    *,
    on_event: Callable[[dict, str], None],
    stop_event: threading.Event,
    log_path: str = LOG_FILE_PATH,
    read_last_lines: int = 200,
) -> None:
    """
    tail -f Falco 输出文件；启动时回放最后 N 行（默认 200），随后持续追尾。
    """
    engine = HostBehaviorEngine()

    if not os.path.exists(log_path):
        open(log_path, "a").close()

    # 启动时先回放最后 N 行，避免“启动后一直等不到新事件”
    for line in _read_last_lines(log_path, read_last_lines):
        if stop_event.is_set():
            return
        event = engine.analyze_event(line)
        if event:
            try:
                on_event(event, line)
            except Exception:
                pass

    with open(log_path, "r", encoding="utf-8", errors="ignore") as f_in:
        f_in.seek(0, 2)  # 追尾
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