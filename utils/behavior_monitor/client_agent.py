"""
客户端行为采集 Agent（在客户端机器运行）：
- 自动判断 Windows/Linux
- 调用对应 host_monitor_* 的 run_forever 采集事件
- 将事件通过 HTTP POST 上报到服务器 /behavior/ingest 入库
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
from datetime import datetime, timezone


# --- 关键修复：确保无论从哪里运行，import utils.xxx 都能成功 ---
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))
# ------------------------------------------------------------


def _default_host_name() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "unknown-client"


def _utc_now_z() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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
    with urllib.request.urlopen(req, timeout=8) as resp:
        _ = resp.read()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True, help="服务器地址，例如 http://10.21.226.213:5000")
    parser.add_argument("--host-name", default=_default_host_name(), help="写入数据库的 host_name（默认 hostname）")
    parser.add_argument("--falco-log", default="/var/log/falco_events.json", help="Linux Falco JSON 文件路径")
    parser.add_argument("--verbose", action="store_true", help="打印上报失败原因（推荐开启排错）")
    parser.add_argument("--ping", action="store_true", help="仅发送一条测试事件到服务器后退出（用于排障）")
    args = parser.parse_args()

    host_name = (args.host_name or "").strip() or _default_host_name()
    stop_event = threading.Event()
    os_name = platform.system().lower()

    def safe_post(ev: dict, raw: str | None):
        try:
            post_event(args.server, host_name, ev, raw)
            if args.verbose:
                print(f"[agent] posted event_type={ev.get('event_type')} host_name={host_name}")
        except Exception as e:
            if args.verbose:
                print(f"[agent] post_event failed: {e}")

    # 启动心跳：让服务器一定能看到该主机（即使 Falco 暂无事件）
    startup_event = {
        "data_source": "host_behavior",
        "timestamp": _utc_now_z(),
        "host_ip": host_name,  # 这里不强求 IP，先占位；host_name 由 payload.host_name 决定
        "event_type": "agent_startup",
        "action": "heartbeat",
        "entities": {"process_name": "client_agent", "pid": 0, "parent_pid": 0, "command_line": ""},
        "behavior_features": {"is_abnormal_parent": False, "has_memory_injection": False},
        "description": f"agent startup ({os_name})",
    }
    safe_post(startup_event, raw=None)

    if args.ping:
        return

    def on_event(ev: dict, raw: str):
        safe_post(ev, raw)

    if os_name == "linux":
        from utils.behavior_monitor.host_monitor_linux import run_forever as linux_run
        linux_run(on_event=on_event, stop_event=stop_event, log_path=args.falco_log)
    elif os_name == "windows":
        from utils.behavior_monitor.host_monitor_windows import run_forever as win_run
        win_run(on_event=on_event, stop_event=stop_event)
    else:
        raise RuntimeError(f"Unsupported OS: {os_name}")


if __name__ == "__main__":
    main()