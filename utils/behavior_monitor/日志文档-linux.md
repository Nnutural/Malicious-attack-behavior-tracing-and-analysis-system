# **1. 安装核心采集引擎 Falco** 

这是你的“眼睛”，负责在内核抓数据。

## Install Falco（主机行为监控开源软件下载流程）——适用ubuntn

​	Regardless of which setup you used above, this section will show you how to  install Falco on a host system. You'll begin by updating the package  repository. Next, you'll install the dialog package. Then you'll install Falco and ensure it's up and running.

### Set up the package repository

- Add the Falco repository key.

```bash
curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | \
sudo gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg
```

- Add the Falco repository.

```bash
sudo bash -c 'cat << EOF > /etc/apt/sources.list.d/falcosecurity.list
deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main
EOF'
```

- Read the repository contents.

```bash
sudo apt-get update -y
```

### Install dialog

- Install *dialog*, which is used by the Falco installer.

```bash
sudo apt-get install -y dialog
```

### Install Falco

- Install the latest Falco version.

```bash
sudo apt-get install -y falco
```

- When prompted, choose the **Modern eBPF** option. This will enable the usage of the modern eBPF-based driver.

  ![Dialog window - Choose the modern eBPF driver](https://falco.org/docs/getting-started/images/dialog-1.png)

- When prompted, choose **Yes**. Although we won't use the functionality in this exercise, this option allows Falco to update its rules automatically.

  ![Dialog window - Choose the follow automatic ruleset updates](https://falco.org/docs/getting-started/images/dialog-2.png)

Wait for the Falco installation to complete - this should only take a few minutes.

### Start Falco

```bash
sudo systemctl start falco-modern-bpf.service
```

### Verify Falco is running

- Make sure the Falco service is running.

```bash
sudo systemctl status falco-modern-bpf.service
```

The output should be similar to the following:

```plain
● falco-modern-bpf.service - Falco: Container Native Runtime Security with modern ebpf
     Loaded: loaded (/usr/lib/systemd/system/falco-modern-bpf.service; enabled; preset: enabled)
     Active: active (running) since Wed 2024-09-18 08:40:04 UTC; 11min ago
       Docs: https://falco.org/docs/
   Main PID: 4751 (falco)
      Tasks: 7 (limit: 2275)
     Memory: 24.7M (peak: 37.1M)
        CPU: 3.913s
     CGroup: /system.slice/falco-modern-bpf.service
             └─4751 /usr/bin/falco -o engine.kind=modern_ebpf

Sep 18 08:40:12 vagrant falco[4751]:    /etc/falco/falco.yaml
Sep 18 08:40:12 vagrant falco[4751]: System info: Linux version 6.8.0-31-generic (buildd@lcy02-amd64-080) (x86_64-linux-gnu-gcc-13 (Ubuntu 13.2.0-23ubuntu4) 13.2.0, GNU ld (GNU Binutils for Ubuntu) 2.42) #31-Ubuntu SMP PREEMPT_DYNAMIC Sat Apr 20 00:40:06 UTC 2024
Sep 18 08:40:12 vagrant falco[4751]: Loading rules from file /etc/falco/falco_rules.yaml
Sep 18 08:40:12 vagrant falco[4751]: Loading rules from file /etc/falco/falco_rules.local.yaml
Sep 18 08:40:12 vagrant falco[4751]: The chosen syscall buffer dimension is: 8388608 bytes (8 MBs)
Sep 18 08:40:12 vagrant falco[4751]: Starting health webserver with threadiness 2, listening on 0.0.0.0:8765
Sep 18 08:40:12 vagrant falco[4751]: Loaded event sources: syscall
Sep 18 08:40:12 vagrant falco[4751]: Enabled event sources: syscall
Sep 18 08:40:12 vagrant falco[4751]: Opening 'syscall' source with modern BPF probe.
Sep 18 08:40:12 vagrant falco[4751]: One ring buffer every '2' CPUs.
```

---



# **2. 配置 Falco 输出 JSON** 

修改配置文件 `/etc/falco/falco.yaml`，让它把日志吐给你的 Python 程序读：

```yaml
json_output: true
file_output:
  enabled: true
  keep_alive: false
  filename: /var/log/falco_events.json
```

<img src="E:\Tencent\wechatchat\xwechat_files\wxid_9pnt7aagjdpq22_3f82\temp\InputTemp\b601804c-4962-4794-ab54-664a98b84bc2.png" alt="b601804c-4962-4794-ab54-664a98b84bc2" style="zoom:67%;" />

<img src="E:\Tencent\wechatchat\xwechat_files\wxid_9pnt7aagjdpq22_3f82\temp\InputTemp\fc9e6136-6948-41a5-81ad-dde7b2776450.png" alt="fc9e6136-6948-41a5-81ad-dde7b2776450" style="zoom:50%;" />

然后重启：`sudo systemctl restart falco-modern-bpf.service`

---



# **3. 安装 Python 分析库**

```bash
pip3 install psutil networkx watchdog
```

**创建虚拟环境** (在你的 `~/XiaoXueQi` 目录下)：

```bash
# 确保在你的项目目录
cd ~/XiaoXueQi

# 创建一个名为 venv 的虚拟环境文件夹
python3 -m venv venv
```

**激活虚拟环境** (关键步骤)：

```bash
source venv/bin/activate
```

**现在安装库** (这时候就可以正常用 pip 了)：

```bash
pip install psutil networkx watchdog
```

<img src="E:\Tencent\wechatchat\xwechat_files\wxid_9pnt7aagjdpq22_3f82\temp\InputTemp\24f58f21-5c97-4dea-86b3-6870b93b51ae.png" alt="24f58f21-5c97-4dea-86b3-6870b93b51ae" style="zoom: 50%;" />

如果运行py脚本时发现下列状况，系文件仅只读（需更改权限）

<img src="E:\Tencent\wechatchat\xwechat_files\wxid_9pnt7aagjdpq22_3f82\temp\InputTemp\26cd803a-d9a7-4ac6-b91c-cc0ce1a2f97b.png" alt="26cd803a-d9a7-4ac6-b91c-cc0ce1a2f97b" style="zoom: 67%;" />

在终端执行：`sudo chmod 644 /var/log/falco_events.json`:(再次执行 `ls -l /var/log/falco_events.json`，你应该能看到权限变成了 `-rw-r--r--`)

**预期结果**： 你应该能看到如下输出，且不再报错：

```
[*] 主机行为监控系统启动 (Kernel Level w/ eBPF)...
[*] 正在构建实时进程行为图谱...
```

(程序会卡在这里等待，这是正常的，因为它在实时监听)

---



# 4.手动触发攻击

```sh
#!/bin/bash

echo -e "\033[1;31m[*] 开始执行真实攻防演示 (Safe Mode)...\033[0m"
echo -e "\033[1;33m[*] 目标: 触发 Falco 内核监控 -> Python 引擎实时分析\033[0m\n"

# 1. 真实触发: 内存注入 (Ptrace)
# 原理: strace 使用 ptrace 系统调用跟踪进程，这是调试行为，也是注入行为
echo "[1/7] 正在模拟: 代码注入 (Ptrace)..."
sudo strace ls > /dev/null 2>&1
sleep 2

# 2. 真实触发: 无文件攻击 (Pipe Execution)
# 原理: 通过管道直接传给 bash 执行，不落地文件，Falco 规则 "Shell only reads stdin"
echo "[2/7] 正在模拟: 无文件执行 (Fileless)..."
echo "echo 'Fileless payload executed'" | /bin/bash
sleep 2

# 3. 真实触发: 文件删除 (痕迹清除)
# 原理: 先创建一个无用的假日志，然后删除它
echo "[3/7] 正在模拟: 痕迹清除 (File Delete)..."
sudo touch /var/log/fake_hack_trace.log
sudo rm /var/log/fake_hack_trace.log
sleep 2

# 4. 真实触发: 文件篡改 (修改配置)
# 原理: 修改 /etc/ 下的文件通常被视为篡改。我们只 touch 一下假文件，不破坏真配置。
echo "[4/7] 正在模拟: 配置篡改 (File Modify)..."
sudo touch /etc/fake_config.conf
# 写入一点数据触发 write
sudo sh -c 'echo "hacked=true" > /etc/fake_config.conf'
sleep 2

# 5. 真实触发: Webshell 落地 (文件创建)
# 原理: 向 /usr/bin/ 或 Web 目录写入文件。Falco 规则 "Write below binary dir"
echo "[5/7] 正在模拟: Webshell 落地 (File Create)..."
sudo touch /usr/bin/fake_webshell_test
sleep 2

# 6. 真实触发: 敏感文件读取
# 原理: 读取 shadow 文件，这是最高危的读取行为
echo "[6/7] 正在模拟: 敏感文件读取 (File Read)..."
sudo cat /etc/shadow > /dev/null
sleep 2

# 7. 真实触发: 网络连接 / 异常进程链
# 原理: 使用 nc 监听端口，或者 python 启动 shell。
# 注意: 为了触发 host_monitor 的 "cmd->powershell" 规则需要修改 monitor 代码
# 这里我们触发一个通用的 "Linux 异常 Shell" (Python 启动 Bash)
echo "[7/7] 正在模拟: 异常进程链/网络连接..."
# 模拟 Python 派生 Shell (常见的提权手法)
python3 -c 'import os; os.system("/bin/ls")'
# 或者尝试建立一个网络连接 (如果安装了 nc)
nc -z 8.8.8.8 53 > /dev/null 2>&1

echo -e "\n\033[1;32m[*] 演示结束! 请检查 host_monitor.py 的输出。\033[0m"
# 清理刚才创建的垃圾文件
sudo rm -f /etc/fake_config.conf /usr/bin/fake_webshell_test
```

测试攻击脚本 sudo .\attack_test.sh查看。



# 5.Falco的Local rule

falco_rules.local.yaml加入规则（文件夹中的两个rule文件可以直接替换原本文件夹中内容）

```
# ================= 演示专用规则 (最终版) =================

# 1. [网络连接] 捕获 nc, curl
- rule: Bishe Network Tool
  desc: Detect network tool execution
  condition: >
    spawned_process and 
    (proc.name in (nc, ncat, curl, wget) or proc.cmdline contains "nc " or proc.cmdline contains "curl")
  output: "Bishe Alert: Suspicious network tool execution (user=%user.name command=%proc.cmdline)"
  priority: WARNING

# 2. [文件删除] 捕获 rm
- rule: Bishe File Deletion
  desc: Detect rm command
  condition: spawned_process and proc.name = rm
  output: "Bishe Alert: File deletion detected (user=%user.name command=%proc.cmdline)"
  priority: WARNING

# 3. [文件创建] 捕获 touch
- rule: Bishe File Creation
  desc: Detect touch command
  condition: spawned_process and proc.name = touch
  output: "Bishe Alert: File creation detected (user=%user.name command=%proc.cmdline)"
  priority: WARNING

# 4. [文件篡改] 放宽条件：只要 cmdline 里同时出现 echo 和 (>> 或 >) 就报警
- rule: Bishe File Modification
  desc: Detect modification via redirection or chmod
  condition: >
    spawned_process and 
    (proc.name = chmod or (proc.cmdline contains "echo" and (proc.cmdline contains ">" or proc.cmdline contains "tee")))
  output: "Bishe Alert: File modification detected (user=%user.name command=%proc.cmdline)"
  priority: WARNING

# 5. [敏感读取] 捕获 cat /etc/shadow
- rule: Bishe Sensitive Read
  desc: Detect sensitive file reading
  condition: spawned_process and (proc.cmdline contains "/etc/shadow" or proc.cmdline contains "/etc/passwd")
  output: "Bishe Alert: Sensitive file access detected (user=%user.name command=%proc.cmdline)"
  priority: WARNING

# 6. [无文件/内存执行] 捕获管道执行 (针对 echo '...' | /bin/bash)
# 当 bash 从管道读取时，通常没有参数，或者被识别为非交互式 shell
- rule: Bishe Fileless Execution
  desc: Detect shell reading from stdin (pipe)
  condition: >
    spawned_process and 
    (proc.name in (bash, sh) and proc.pname in (bash, sh) and not proc.cmdline contains "real_attack.sh")
  output: "Bishe Alert: Fileless execution via pipe detected (user=%user.name command=%proc.cmdline)"
  priority: WARNING

# 7. [异常 Shell] 放宽条件：只要 cmdline 里有 python 和 sh
- rule: Bishe Python Shell
  desc: Detect python spawning shell
  condition: >
    spawned_process and 
    ((proc.name startswith python) and (proc.cmdline contains "sh" or proc.cmdline contains "bash"))
  output: "Bishe Alert: Python spawning abnormal shell (user=%user.name command=%proc.cmdline)"
  priority: WARNING

```



# 6.主机行为监控部分代码

host_monitor.py代码

```python
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

```

