"""
客户端行为采集 Agent（在客户端机器运行）：
- 自动判断 Windows/Linux
- 调用对应 host_monitor_* 的 run_forever 采集事件
- 将事件通过 HTTP POST 上报到服务器 /behavior/ingest 入库

用法示例（在项目根目录执行）：
  python utils/behavior_monitor/client_agent.py --server http://192.168.1.10:5000 --host-name client-01
"""

from __future__ import annotations

import argparse
import json
import platform
import socket
import threading
import urllib.request
import sys
from pathlib import Path


# --- 关键修复：确保无论从哪里运行，import utils.xxx 都能成功 ---
_PROJECT_ROOT = Path(__file__).resolve().parents[2]  # .../utils/behavior_monitor/client_agent.py -> 项目根目录
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))
# ------------------------------------------------------------


def _default_host_name() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "unknown-client"


def post_event(server: str, host_name: str, event: dict, raw: str | None) -> None:
    url = server.rstrip("/") + "/behavior/ingest"
    payload = {"host_name": host_name, "event": event, "raw": raw}
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        _ = resp.read()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True, help="服务器地址，例如 http://10.21.226.213:5000")
    parser.add_argument("--host-name", default=_default_host_name(), help="写入数据库的 host_name（默认 hostname）")
    parser.add_argument("--falco-log", default="/var/log/falco_events.json", help="Linux Falco JSON 文件路径")
    parser.add_argument("--verbose", action="store_true", help="打印上报失败原因（推荐开启排错）")
    args = parser.parse_args()

    stop_event = threading.Event()
    os_name = platform.system().lower()

    def on_event(ev: dict, raw: str):
        try:
            post_event(args.server, args.host_name, ev, raw)
        except Exception as e:
            if args.verbose:
                print(f"[agent] post_event failed: {e}")

    if os_name == "linux":
        from utils.behavior_monitor.host_monitor_linux import run_forever as linux_run

        linux_run(on_event=on_event, stop_event=stop_event, log_path=args.falco_log)
    elif os_name == "windows":
        from utils.behavior_monitor.host_monitor_windows import run_forever as win_run

        # 注意：host_monitor_windows.py 的 run_forever 需要 stop_event 参数
        win_run(on_event=on_event, stop_event=stop_event)
    else:
        raise RuntimeError(f"Unsupported OS: {os_name}")


if __name__ == "__main__":
    main()