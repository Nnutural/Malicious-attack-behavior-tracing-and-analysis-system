"""
客户端行为采集 Agent（在客户端机器运行）：
- 自动判断 Windows/Linux
- 调用对应 host_monitor_* 的 run_forever 采集事件
- 将事件通过 HTTP POST 上报到服务器 /behavior/ingest 入库

增强：对 process_create 事件补齐 entities.listen_ports（可选依赖 psutil）
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


def _enrich_listen_ports(event: dict) -> None:
    """
    给 event['entities']['listen_ports'] 补齐监听端口快照。
    - 仅对 event_type=process_create 尝试
    - 未安装 psutil 或权限不足时保持 []
    """
    try:
        if not isinstance(event, dict):
            return
        if event.get("event_type") != "process_create":
            return
        ent = event.get("entities")
        if not isinstance(ent, dict):
            return

        pid = ent.get("pid")
        if not isinstance(pid, int) or pid <= 0:
            return

        # 确保字段存在
        if "listen_ports" not in ent or not isinstance(ent.get("listen_ports"), list):
            ent["listen_ports"] = []

        try:
            import psutil  # type: ignore
        except Exception:
            return

        ports: set[int] = set()
        for c in psutil.net_connections(kind="inet"):
            if c.pid != pid:
                continue
            if getattr(c, "status", None) != psutil.CONN_LISTEN:
                continue
            laddr = getattr(c, "laddr", None)
            if not laddr:
                continue
            port = None
            try:
                port = int(laddr.port)  # type: ignore[attr-defined]
            except Exception:
                try:
                    port = int(laddr[1])  # type: ignore[index]
                except Exception:
                    port = None
            if port is not None and 0 < port < 65536:
                ports.add(port)

        ent["listen_ports"] = sorted(ports)
    except Exception:
        return


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
            _enrich_listen_ports(ev)
            post_event(args.server, host_name, ev, raw)
            if args.verbose:
                ent = ev.get("entities") or {}
                print(
                    f"[agent] posted event_type={ev.get('event_type')} host_name={host_name} "
                    f"pid={ent.get('pid')} listen_ports={ent.get('listen_ports')}"
                )
        except Exception as e:
            if args.verbose:
                print(f"[agent] post_event failed: {e}")

    startup_event = {
        "data_source": "host_behavior",
        "timestamp": _utc_now_z(),
        "host_ip": host_name,
        "event_type": "agent_startup",
        "action": "heartbeat",
        "entities": {
            "process_name": "client_agent",
            "pid": 0,
            "parent_process": None,
            "parent_pid": 0,
            "command_line": "",
            "hash": None,
            "user": None,
            "file_path": None,
            "listen_ports": [],
            "registry_key": None,
            "registry_value_name": None,
            "registry_value_data": None,
            "src_ip": None,
            "src_port": None,
            "dst_ip": None,
            "dst_port": None,
            "protocol": None,
        },
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