from __future__ import annotations

import logging
import platform
import threading
import time
import socket
from typing import Callable

from utils.behavior_monitor.service.hostbehaviors_ingest import ingest_host_behavior_event

logger = logging.getLogger(__name__)


def _get_host_name() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "unknown"


class BehaviorMonitorManager:
    """
    单例式 Manager：
    - start(): 后台线程启动监控（自动判断 OS）
    - stop(): 停止
    - status(): 状态
    """

    def __init__(self) -> None:
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._running_lock = threading.Lock()
        self._running = False
        self._started_at: float | None = None

        self._inserted = 0
        self._skipped = 0
        self._errors = 0

    def is_running(self) -> bool:
        with self._running_lock:
            return bool(self._running)

    def status(self) -> dict:
        now = time.time()
        with self._running_lock:
            started_at = self._started_at
            running = self._running
        return {
            "running": running,
            "started_at": started_at,
            "uptime_sec": (now - started_at) if (running and started_at) else 0,
            "counters": {"inserted": self._inserted, "skipped": self._skipped, "errors": self._errors},
        }

    def start(self) -> dict:
        if self.is_running():
            return {"ok": True, "already_running": True, "status": self.status()}

        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, name="BehaviorMonitorThread", daemon=True)

        with self._running_lock:
            self._running = True
            self._started_at = time.time()

        self._thread.start()
        return {"ok": True, "already_running": False, "status": self.status()}

    def stop(self) -> dict:
        self._stop_event.set()

        # 线程会自己退出；这里不强 join（避免阻塞请求）
        with self._running_lock:
            self._running = False

        return {"ok": True, "status": self.status()}

    def _on_event(self, event: dict, raw_content: str | None, host_name: str | None) -> None:
        r = ingest_host_behavior_event(event=event, raw_content=raw_content, host_name=host_name)
        self._inserted += int(r.get("inserted") or 0)
        self._skipped += int(r.get("skipped") or 0)
        self._errors += int(r.get("errors") or 0)

    def _run_loop(self) -> None:
        os_name = platform.system().lower()
        host_name = _get_host_name()

        try:
            if os_name == "linux":
                from utils.behavior_monitor.host_monitor_linux import run_forever as linux_run

                linux_run(
                    on_event=lambda ev, raw: self._on_event(ev, raw, host_name),
                    stop_event=self._stop_event,
                )
            elif os_name == "windows":
                from utils.behavior_monitor.host_monitor_windows import run_forever as win_run

                win_run(
                    on_event=lambda ev, raw: self._on_event(ev, raw, host_name),
                    stop_event=self._stop_event,
                )
            else:
                logger.error("Unsupported OS: %s", os_name)
        except Exception as exc:
            logger.exception("Behavior monitor crashed: %s", exc)
        finally:
            with self._running_lock:
                self._running = False