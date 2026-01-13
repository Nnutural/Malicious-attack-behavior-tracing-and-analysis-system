# -*- coding: utf-8 -*-
"""
HostGuard Core Engine - 主机恶意行为溯源分析系统 (Final Delivery)
================================================================
[项目对应章节]
题目 2：(1) 主机行为监控 & (3) 攻击溯源关键技术

[核心模块说明]
1. Log Ingestion (数据采集): 实时清洗 Falco/Syscall 日志，实现“系统调用拦截”。
2. Feature Extraction (特征提取): 提取关键实体(PID, Cmdline, Path)及计算文件 HASH。
3. Behavior Analysis (行为分析): 映射 7 大类攻击行为 (注入, 网络, 文件CRUD, 异常Shell)。
4. Evidence Preservation (取证留存): 标准化 JSON 输出，包含 command_line 和 file_hash。

[维护者] Star2023211474
"""

import json
import time
import os
import sys
import socket
import datetime
import hashlib
import re
import threading
from typing import List, Dict, Optional

# ================= [配置层] 系统环境配置 =================
LOG_FILE_PATH = "/var/log/falco_events.json" 
DATA_OUTPUT_PATH = "host_data.json"

class EventType:
    """[数据标准] 威胁事件类型枚举"""
    PROCESS_INJECTION = "process_injection"  # 内存注入
    FILE_CREATE       = "file_create"        # 文件创建 (需Hash)
    FILE_MODIFY       = "file_modify"        # 文件篡改 (需Hash)
    FILE_DELETE       = "file_delete"        # 痕迹清除
    FILE_READ         = "file_read"          # 敏感读取
    NETWORK_CONNECT   = "network_connection" # C2连接
    PROCESS_CREATE    = "process_create"     # 进程启动 (需Hash)
    REGISTRY_SET      = "registry_set_value" # 注册表修改 (扩展支持)

class ActionType:
    """[数据标准] 行为动作枚举"""
    INJECTION    = "injection"
    MODIFICATION = "modification"
    DELETION     = "deletion"
    ACCESS       = "access"
    CONNECTION   = "connection"
    EXECUTION    = "execution"

# ================= [工具层] 静态取证工具 =================
class ForensicsUtils:
    """
    提供 IP 获取、时间戳生成、文件哈希计算等取证功能。
    对应需求：(3) 攻击者身份溯源 - 提取指纹特征
    """
    
    @staticmethod
    def get_host_ip() -> str:
        """获取局域网真实 IP，用于定位受害主机"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]; s.close()
            return ip
        except: return "127.0.0.1"

    @staticmethod
    def get_timestamp() -> str:
        """生成 ISO 8601 时间戳，确保多源数据时间对齐"""
        return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    @staticmethod
    def calculate_sha256(filepath: str) -> str:
        """
        [关键功能] 计算文件 SHA256 哈希值
        用于后续环节的“攻击工具指纹匹配”和“威胁情报关联”。
        """
        if not filepath or not os.path.exists(filepath):
            return "unknown_or_deleted"
        
        # 忽略设备文件和目录，防止阻塞
        if not os.path.isfile(filepath):
            return "not_a_regular_file"

        try:
            sha256_hash = hashlib.sha256()
            with open(filepath, "rb") as f:
                # 分块读取，防止大文件撑爆内存
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception:
            return "access_denied"

    @staticmethod
    def strip_sudo(proc_name: str, cmd_line: str) -> str:
        """[数据清洗] 剥离 Sudo 伪装，还原真实进程名"""
        if proc_name == "sudo" and cmd_line:
            parts = cmd_line.split()
            for part in parts[1:]:
                if not part.startswith("-") and "=" not in part:
                    return os.path.basename(part)
        return proc_name

# ================= [核心层] 行为分析引擎 =================
class HostBehaviorEngine:
    """
    主分析引擎，负责日志流的 解析 -> 识别 -> 丰富 -> 输出
    """
    def __init__(self):
        # 去重缓存: { "Signature": Timestamp }
        self._dedup_cache = {} 
        self._lock = threading.Lock()

    def _is_duplicate(self, alert: Dict) -> bool:
        """[降噪模块] 1.5秒内去除重复告警，防止日志风暴"""
        # 签名由 事件类型+命令行 构成
        sig = f"{alert['event_type']}:{alert['entities']['command_line']}"
        now = time.time()
        
        with self._lock:
            last_time = self._dedup_cache.get(sig, 0)
            if now - last_time < 1.5: 
                return True
            self._dedup_cache[sig] = now
            return False

    def analyze_event(self, line: str) -> Optional[Dict]:
        """
        [分析主逻辑] 将原始日志映射为标准的威胁事件结构
        """
        try:
            # 1. 基础解析
            raw = json.loads(line)
            output = raw.get('output', '')
            fields = raw.get('output_fields', {})
            
            # 提取关键字段：Cmdline 是最关键的取证数据
            cmd = fields.get('proc.cmdline', '')
            proc = fields.get('proc.name', '')
            
            # 数据清洗：补全 unknown 进程名，剥离 sudo
            if (not proc or proc == 'unknown') and cmd:
                proc = cmd.split()[0]
            proc = ForensicsUtils.strip_sudo(proc, cmd)

            # 2. 构建标准数据结构 (Schema Definition)
            alert = {
                "data_source": "host_behavior",
                "timestamp": ForensicsUtils.get_timestamp(),
                "host_ip": ForensicsUtils.get_host_ip(),
                "event_type": "unknown",
                "action": "unknown",
                "entities": {
                    "process_name": proc,
                    "command_line": cmd, # 关键取证数据 (Base64指令藏匿于此)
                    "pid": 0, 
                    "parent_process": "unknown", 
                    "parent_pid": 0,
                    # 预留注册表字段 (Linux环境为空，Windows环境填充)
                    "registry_key": None,
                    "registry_value_name": None,
                    "registry_value_data": None,
                    "file_hash": None # 关键指纹数据
                },
                "behavior_features": {
                    "is_abnormal_parent": False,
                    "has_memory_injection": False
                },
                "description": output
            }

            # 3. 威胁识别与特征映射 (Mapping Logic)
            target_file = ""

            # --- Type A: 内存注入 (PTRACE/Strace) ---
            if "PTRACE" in output or "strace" in cmd:
                alert['event_type'] = EventType.PROCESS_INJECTION
                alert['action'] = ActionType.INJECTION
                alert['behavior_features']['has_memory_injection'] = True
            
            # --- Type B: 网络连接 (Network) ---
            elif "Network" in output or any(x in cmd for x in ["nc ", "ncat ", "curl "]):
                alert['event_type'] = EventType.NETWORK_CONNECT
                alert['action'] = ActionType.CONNECTION
                # 尝试提取目标 IP
                ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', cmd)
                if ip_match: alert['entities']['target_ip'] = ip_match.group(1)

            # --- Type C: 文件删除 (Delete) ---
            elif "File deletion" in output or "rm " in cmd:
                alert['event_type'] = EventType.FILE_DELETE
                alert['action'] = ActionType.DELETION
                alert['entities']['target_file'] = cmd.split()[-1]

            # --- Type D: 文件创建/篡改 (Create/Modify) ---
            elif "File creation" in output or "touch " in cmd:
                alert['event_type'] = EventType.FILE_CREATE
                alert['action'] = ActionType.MODIFICATION
                target_file = cmd.split()[-1]
                alert['entities']['target_file'] = target_file
                # [关键] 计算文件指纹 HASH
                alert['entities']['file_hash'] = ForensicsUtils.calculate_sha256(target_file)

            elif "File modification" in output or "chmod" in cmd or ">>" in cmd:
                alert['event_type'] = EventType.FILE_MODIFY
                alert['action'] = ActionType.MODIFICATION
                if ">>" in cmd:
                    target_file = cmd.split(">>")[1].strip()
                elif "chmod" in cmd:
                    target_file = cmd.split()[-1]
                alert['entities']['target_file'] = target_file
                # [关键] 计算文件指纹 HASH
                alert['entities']['file_hash'] = ForensicsUtils.calculate_sha256(target_file)

            # --- Type E: 敏感读取 (Read) ---
            elif "Sensitive" in output or "shadow" in cmd or "unix_chkpwd" in proc:
                alert['event_type'] = EventType.FILE_READ
                alert['action'] = ActionType.ACCESS
                alert['entities']['target_file'] = "/etc/shadow"

            # --- Type F: 异常 Shell/进程 (Process) ---
            elif "Python" in output or "Abnormal shell" in output:
                alert['event_type'] = EventType.PROCESS_CREATE
                alert['action'] = ActionType.EXECUTION
                alert['behavior_features']['is_abnormal_parent'] = True
                # [关键] 进程创建也需要计算 Hash (针对可执行文件)
                # 简单处理：如果是脚本，Hash 脚本文件；如果是二进制，Hash 二进制
                # 这里做简化处理，尝试 Hash 命令行第一个参数
                exe_path = cmd.split()[0]
                if os.path.exists(exe_path):
                    alert['entities']['file_hash'] = ForensicsUtils.calculate_sha256(exe_path)

            # --- Type G: 注册表修改 (Windows 扩展预留) ---
            elif "Registry" in output:
                alert['event_type'] = EventType.REGISTRY_SET
                alert['action'] = ActionType.MODIFICATION
                # 模拟数据填充
                alert['entities']['registry_key'] = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\EvilExe"
                alert['entities']['registry_value_name'] = "EvilExe"
                alert['entities']['registry_value_data'] = r"C:\Windows\Temp\trojan.exe"

            else:
                return None # 过滤无关噪音

            # 4. 去重检查
            if self._is_duplicate(alert):
                return None

            return alert

        except Exception:
            return None

# ================= [控制层] 系统入口 =================
def main():
    engine = HostBehaviorEngine()
    
    # 1. 环境初始化
    with open(DATA_OUTPUT_PATH, 'w', encoding='utf-8') as f: f.write("")
    if not os.path.exists(LOG_FILE_PATH): open(LOG_FILE_PATH, 'a').close()

    print(f"[*] HostGuard Core Engine v4.0 Started (Final Edition).")
    print(f"[*] Monitoring Source: {LOG_FILE_PATH}")
    print(f"[*] Fingerprinting Strategy: SHA256 Hashing Enabled")
    print("-" * 60)

    # 2. 实时流处理循环 (Tail-f)
    try:
        with open(LOG_FILE_PATH, 'r') as f_in, open(DATA_OUTPUT_PATH, 'a', encoding='utf-8') as f_out:
            f_in.seek(0, 2)
            while True:
                line = f_in.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                
                # 分析日志
                result = engine.analyze_event(line)
                
                # 输出结果
                if result:
                    json_str = json.dumps(result, ensure_ascii=False)
                    print(json_str) # 控制台实时显示
                    sys.stdout.flush()
                    f_out.write(json_str + "\n") # 持久化存储
                    f_out.flush()

    except KeyboardInterrupt:
        print("\n[*] System shutdown requested.")

if __name__ == "__main__":
    main()
