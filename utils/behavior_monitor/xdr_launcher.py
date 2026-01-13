# -*- coding: utf-8 -*-
"""
HostGuard XDR Launcher - 智能环境感知启动器
==========================================
[功能]
1. 自动识别操作系统 (Windows/Linux)。
2. 自动检查环境依赖 (Falco/Sysmon/Python库)。
3. 守护进程模式启动对应的分析引擎。

[维护者] Star2023211474
"""

import sys
import os
import platform
import subprocess
import time


def check_environment():
    """环境预检"""
    system = platform.system()
    print(f"[*] Detected OS: {system}")

    if system == "Linux":
        # 检查 Falco 日志文件是否存在
        if not os.path.exists("/var/log/falco_events.json"):
            print("[!] Warning: Falco log not found. Creating dummy file for testing...")
            try:
                with open("/var/log/falco_events.json", "a") as f:
                    pass
            except PermissionError:
                print("[!] Error: Permission denied. Please run as root (sudo).")
                sys.exit(1)
        return "host_monitor_linux.py"

    elif system == "Windows":
        # 检查是否安装 pywin32
        try:
            import win32evtlog
        except ImportError:
            print("[!] Error: Missing dependency 'pywin32'.")
            print("    Please run: pip install pywin32")
            sys.exit(1)
        return "host_monitor_windows.py"

    else:
        print(f"[!] Error: Unsupported OS '{system}'")
        sys.exit(1)


def main():
    print("=" * 50)
    print("   HostGuard XDR System - Initialization")
    print("=" * 50)

    target_script = check_environment()

    print(f"[*] Launching Engine: {target_script}...")
    print("-" * 50)

    # 启动对应脚本
    try:
        # 使用当前 Python 解释器启动子进程
        if platform.system() == "Windows":
            subprocess.run([sys.executable, target_script], check=True)
        else:
            # Linux 下建议直接 exec 替换当前进程，节省资源
            os.execl(sys.executable, sys.executable, target_script)

    except KeyboardInterrupt:
        print("\n[*] Launcher stopped.")
    except Exception as e:
        print(f"\n[!] Execution Error: {e}")


if __name__ == "__main__":
    main()