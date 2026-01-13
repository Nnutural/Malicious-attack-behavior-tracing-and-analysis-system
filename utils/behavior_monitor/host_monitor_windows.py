# -*- coding: utf-8 -*-
"""
HostGuard Windows Engine (v5.0 Ultimate Fix)
============================================
[修复说明]
1. 修复 XML 解析核心 BUG: 兼容 xmlns 使用单引号(')的情况。
   原正则: xmlns="[^"]+" -> 导致单引号环境解析失败。
   新正则: xmlns=['"][^'"]+['\"] -> 同时兼容单双引号。
2. 保持严格 Schema 输出。
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
import xml.etree.ElementTree as ET
from typing import Dict, Optional, List

# [依赖检查] 确保 pywin32 库已安装，这是调用 Windows API 的基础
try:
    import win32evtlog
    import win32event
    import win32con
except ImportError:
    print("[!] Fatal Error: 'pywin32' library not found.")
    sys.exit(1)

# ================= [配置] =================
DATA_OUTPUT_PATH = "host_data.json" # 行为日志落盘路径
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational" # 监听 Sysmon 核心通道
DEBUG_MODE = False # 修复后可以关掉了

# ================= [数据标准定义] =================
class EventType:
    """[标准] 定义毕设要求的 7 类威胁行为类型"""
    PROCESS_CREATE    = "process_create"     # 对应进程链分析
    FILE_CREATE       = "file_create"        # 对应文件落地监控
    FILE_MODIFY       = "file_modify"        # 对应文件篡改监控
    FILE_DELETE       = "file_delete"        # 对应痕迹清除监控
    FILE_READ         = "file_read"          # 对应敏感读取监控
    REGISTRY_SET      = "registry_set_value" # 对应持久化检测
    PROCESS_INJECTION = "process_injection"  # 对应内存注入检测
    NETWORK_CONNECT   = "network_connection" # 对应网络外连监控

class ActionType:
    """[标准] 定义行为动作原语"""
    EXECUTION    = "execution"
    MODIFICATION = "modification"
    DELETION     = "deletion"
    ACCESS       = "access"
    CONNECTION   = "connection"
    INJECTION    = "injection"

# ================= [取证工具箱] =================
class ForensicsUtils:
    @staticmethod
    def get_host_ip() -> str:
        """获取本机 IP 用于定位受害主机"""
        try: return socket.gethostbyname(socket.gethostname())
        except: return "127.0.0.1"

    @staticmethod
    def get_timestamp_iso(raw_time_str=None) -> str:
        """[标准化] 将时间转换为 ISO 8601 格式，统一时间基准"""
        if raw_time_str:
            try: return raw_time_str.replace(" ", "T") + "Z"
            except: pass
        return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    @staticmethod
    def calculate_sha256(filepath: str) -> Optional[str]:
        """[指纹计算] 计算文件 Hash，增加文件锁异常处理机制"""
        if not filepath or not os.path.exists(filepath): return None
        if not os.path.isfile(filepath): return None
        try:
            sha256 = hashlib.sha256()
            with open(filepath, "rb") as f:
                # 分块读取，防止大文件耗尽内存
                for block in iter(lambda: f.read(4096), b""):
                    sha256.update(block)
            return sha256.hexdigest()
        except: return None # 文件被占用时忽略

# ================= [核心分析引擎] =================
class WindowsBehaviorEngine:
    def __init__(self):
        # 保持文件句柄常开，提高高频日志写入性能
        self.file_handle = open(DATA_OUTPUT_PATH, 'a', encoding='utf-8')
        
        # [核心修复] 正则表达式：同时匹配 xmlns='...' 和 xmlns="..."
        # 目的: 移除 XML 命名空间，确保 ElementTree 能正确解析 Tag
        self.ns_pattern = re.compile(r" xmlns=['\"][^'\"]+['\"]")

    def _parse_xml_event(self, xml_content: str) -> Dict:
        """[ETL] 清洗并解析原始 XML 日志"""
        data = {}
        try:
            # 1. 移除 Namespace (兼容单双引号)
            xml_content = self.ns_pattern.sub('', xml_content, count=1)
            root = ET.fromstring(xml_content)
            
            # 2. 提取 EventID (事件类型标识)
            sys_node = root.find("System")
            if sys_node is not None:
                eid = sys_node.find("EventID")
                if eid is not None: data['EventID'] = int(eid.text)
            
            # 3. 提取 EventData (核心负载数据)
            for item in root.findall(".//EventData/Data"):
                name = item.attrib.get("Name")
                text = item.text
                if name: data[name] = text if text else ""
                
        except Exception:
            pass # 忽略解析失败的脏数据，保证系统稳定
        return data

    def process_alert(self, raw_data: Dict):
        """[逻辑映射] 将 Sysmon ID 映射为标准威胁事件"""
        event_id = raw_data.get('EventID')
        if not event_id: return

        # [实体提取] 提取进程、父进程、命令行等关键取证数据
        image_path = raw_data.get('Image', '')
        process_name = os.path.basename(image_path)
        parent_path = raw_data.get('ParentImage', '')
        parent_name = os.path.basename(parent_path)
        
        # [Schema构建] 初始化符合接口规范的 JSON 结构
        alert = {
            "data_source": "host_behavior",
            "timestamp": ForensicsUtils.get_timestamp_iso(raw_data.get('UtcTime')),
            "host_ip": ForensicsUtils.get_host_ip(),
            "event_type": "unknown",
            "action": "unknown",
            "entities": {
                "process_name": process_name,
                "pid": int(raw_data.get('ProcessId', 0)),
                "parent_process": parent_name,
                "parent_pid": int(raw_data.get('ParentProcessId', 0)),
                "command_line": raw_data.get('CommandLine', ''),
                "file_hash": None,      # 动态填充
                "target_file": None,    # 动态填充
                "target_ip": None,      # 动态填充
                "registry_key": None    # 动态填充
            },
            "behavior_features": {
                "is_abnormal_parent": False,
                "has_memory_injection": False
            },
            "description": f"Sysmon Event {event_id}"
        }

        matched = False

        # [ID 1] 进程创建 (Process Chain)
        if event_id == 1:
            alert['event_type'] = EventType.PROCESS_CREATE
            alert['action'] = ActionType.EXECUTION
            
            # [Hash提取] 优先使用 Sysmon 自带的 Hash
            hashes = raw_data.get('Hashes', '')
            if 'SHA256=' in hashes:
                try: alert['entities']['file_hash'] = hashes.split('SHA256=')[1].split(',')[0]
                except: pass
            
            # [异常检测] 识别脚本/文档程序启动 Shell 的异常行为
            p_lower = parent_name.lower()
            c_lower = process_name.lower()
            if ("python" in p_lower or "word" in p_lower) and ("cmd" in c_lower or "powershell" in c_lower):
                alert['behavior_features']['is_abnormal_parent'] = True
                alert['description'] = f"Suspicious spawn: {parent_name} -> {process_name}"
            
            matched = True # 记录所有进程创建，方便演示

        # [ID 3] 网络连接 (Network)
        elif event_id == 3:
            alert['event_type'] = EventType.NETWORK_CONNECT
            alert['action'] = ActionType.CONNECTION
            alert['entities']['target_ip'] = raw_data.get('DestinationIp')
            alert['description'] = f"Network connection to {alert['entities']['target_ip']}"
            matched = True

        # [ID 11] 文件创建 (File Ops)
        elif event_id == 11:
            target_file = raw_data.get('TargetFilename', '')
            alert['event_type'] = EventType.FILE_CREATE
            alert['action'] = ActionType.MODIFICATION
            alert['entities']['target_file'] = target_file
            # [实时计算] 计算落地文件的 Hash
            alert['entities']['file_hash'] = ForensicsUtils.calculate_sha256(target_file)
            alert['description'] = f"File created: {target_file}"
            
            # [策略] 只要后缀匹配脚本或可执行文件就记录
            if target_file.endswith(('.txt', '.exe', '.bat', '.ps1', '.php', '.jsp')):
                matched = True

        # [ID 12-14] 注册表操作 (Persistence)
        elif event_id in [12, 13, 14]:
            alert['event_type'] = EventType.REGISTRY_SET
            alert['action'] = ActionType.MODIFICATION
            alert['entities']['registry_key'] = raw_data.get('TargetObject', '')
            details = raw_data.get('Details', '')
            if details: alert['entities']['registry_value_data'] = details
            matched = True

        # [ID 8] 进程注入 (Injection)
        elif event_id == 8:
            alert['event_type'] = EventType.PROCESS_INJECTION
            alert['action'] = ActionType.INJECTION
            alert['behavior_features']['has_memory_injection'] = True
            matched = True

        # [ID 23] 文件删除 (Anti-Forensics)
        elif event_id == 23:
            alert['event_type'] = EventType.FILE_DELETE
            alert['action'] = ActionType.DELETION
            alert['entities']['target_file'] = raw_data.get('TargetFilename')
            matched = True

        # [输出] 以 JSON List 格式写入文件 (NDJSON)
        if matched:
            wrapper = [alert]
            json_str = json.dumps(wrapper, ensure_ascii=False)
            print(f"[WIN] {json_str}")
            self.file_handle.write(json_str + "\n")
            self.file_handle.flush() # 强制刷新缓冲区，确保实时写入

# ================= [回调入口] =================
def on_event_callback(action, context, event_handle):
    """[回调] Windows 产生新日志时自动触发此函数"""
    if action == win32evtlog.EvtSubscribeActionDeliver:
        try:
            xml_content = win32evtlog.EvtRender(event_handle, win32evtlog.EvtRenderEventXml)
            context._parse_xml_event(xml_content) # 解析 XML
            context.process_alert(context._parse_xml_event(xml_content)) # 处理逻辑
        except Exception:
            pass # 避免回调异常导致监控线程退出

# ================= [主程序] =================
def main():
    print("=" * 60)
    print("   HostGuard Windows Engine (v5.0 Ultimate)")
    print("=" * 60)
    
    engine = WindowsBehaviorEngine()

    try:
        # [核心] 订阅 Sysmon 通道 (Push模式)
        subscription = win32evtlog.EvtSubscribe(
            SYSMON_CHANNEL,
            win32evtlog.EvtSubscribeToFutureEvents, # 仅监听新事件
            None,
            on_event_callback,
            engine,
            None,
            None
        )
        print("[*] Engine Started. Listening for new threats...")
        
        # 主线程保活，等待回调触发
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[*] Stopped.")
    except Exception as e:
        print(f"\n[!] Error: {e}")

if __name__ == "__main__":
    main()