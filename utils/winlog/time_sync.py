"""Soft time sync service/client with persisted offset state."""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .state_store import StateStore

logger = logging.getLogger(__name__)

DEFAULT_TIME_SYNC_PORT = int(os.environ.get("TIME_SYNC_PORT", "18080"))
DEFAULT_TIME_SYNC_BIND = os.environ.get("TIME_SYNC_BIND", "0.0.0.0")
DEFAULT_TIME_SYNC_SAMPLES = int(os.environ.get("TIME_SYNC_SAMPLES", "10"))
DEFAULT_TIME_SYNC_TIMEOUT_SEC = float(os.environ.get("TIME_SYNC_TIMEOUT_SEC", "2.0"))

_STATE_PATH = Path(__file__).resolve().parent / ".state" / "time_sync_state.json"
_STATE_KEY = "clock_sync"


def _utc_now_z() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_sync_state() -> dict[str, Any]:
    store = StateStore(path=_STATE_PATH)
    data = store.get(_STATE_KEY)
    return data if isinstance(data, dict) else {}


def save_sync_state(
    *,
    offset_ms: float,
    delay_ms: float,
    source_ip: str,
    last_sync_utc: str,
) -> None:
    store = StateStore(path=_STATE_PATH)
    store.set(
        _STATE_KEY,
        {
            "offset_ms": offset_ms,
            "delay_ms": delay_ms,
            "source_ip": source_ip,
            "last_sync_utc": last_sync_utc,
        },
    )
    store.flush()


def get_last_sync_state() -> dict[str, Any]:
    data = _load_sync_state()
    offset = data.get("offset_ms")
    delay = data.get("delay_ms")
    source_ip = data.get("source_ip")
    last_sync_utc = data.get("last_sync_utc")
    return {
        "offset_ms": float(offset) if offset is not None else 0.0,
        "delay_ms": float(delay) if delay is not None else None,
        "source_ip": str(source_ip) if source_ip else None,
        "last_sync_utc": str(last_sync_utc) if last_sync_utc else None,
    }


class _TimeSyncHandler(BaseHTTPRequestHandler):
    server_version = "TimeSyncHTTP/1.0"

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path != "/timesync":
            self.send_response(404)
            self.end_headers()
            return

        t2 = time.time_ns()
        t3 = time.time_ns()
        payload = json.dumps({"t2": t2, "t3": t3}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: Any) -> None:
        return


class TimeServiceManager:
    def __init__(self, *, bind_addr: str = DEFAULT_TIME_SYNC_BIND, port: int = DEFAULT_TIME_SYNC_PORT) -> None:
        self._bind_addr = bind_addr
        self._port = port
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._server: ThreadingHTTPServer | None = None
        self._last_error: str | None = None

    def start(self) -> dict[str, Any]:
        with self._lock:
            if self._thread and self._thread.is_alive():
                return self.status()
            try:
                server = ThreadingHTTPServer((self._bind_addr, self._port), _TimeSyncHandler)
                server.daemon_threads = True
                thread = threading.Thread(target=server.serve_forever, name="TimeSyncServer", daemon=True)
                thread.start()
                self._server = server
                self._thread = thread
                self._last_error = None
            except OSError as exc:
                self._last_error = str(exc)
                logger.warning("启动时间同步服务失败: %s", exc)
        return self.status()

    def status(self) -> dict[str, Any]:
        running = self._thread is not None and self._thread.is_alive()
        return {
            "running": running,
            "port": self._port,
            "bind_addr": self._bind_addr,
            "last_error": self._last_error,
        }


@dataclass
class _SampleResult:
    offset_ms: float
    delay_ms: float
    rtt_ms: float


class TimeSyncManager:
    def __init__(
        self,
        *,
        samples: int = DEFAULT_TIME_SYNC_SAMPLES,
        timeout_sec: float = DEFAULT_TIME_SYNC_TIMEOUT_SEC,
    ) -> None:
        self._samples = max(1, samples)
        self._timeout_sec = max(0.2, timeout_sec)
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._status: dict[str, Any] = {
            "running": False,
            "started_at": None,
            "finished_at": None,
            "ok": None,
            "message": None,
            "offset_ms": None,
            "delay_ms": None,
            "source_ip": None,
        }

    def start_one_shot_sync(self, *, target_ip: str, port: int) -> dict[str, Any]:
        if not target_ip:
            return {"started": False, "message": "目标地址为空"}
        with self._lock:
            if self._status.get("running"):
                status = dict(self._status)
                status["started"] = False
                status["message"] = "已有任务在进行"
                return status
            self._status.update(
                {
                    "running": True,
                    "started_at": _utc_now_z(),
                    "finished_at": None,
                    "ok": None,
                    "message": None,
                    "offset_ms": None,
                    "delay_ms": None,
                    "source_ip": target_ip,
                }
            )
            thread = threading.Thread(
                target=self._run_sync,
                args=(target_ip, port),
                name="TimeSyncClient",
                daemon=True,
            )
            self._thread = thread
            thread.start()
            status = dict(self._status)
            status["started"] = True
            return status

    def status(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._status)

    def _run_sync(self, target_ip: str, port: int) -> None:
        ok = False
        offset_ms = None
        delay_ms = None
        message = None
        try:
            sample = self._perform_sync(target_ip, port)
            if sample is None:
                raise RuntimeError("采样不足")
            ok = True
            offset_ms = sample.offset_ms
            delay_ms = sample.delay_ms
            message = "OK"
            save_sync_state(
                offset_ms=offset_ms,
                delay_ms=delay_ms,
                source_ip=target_ip,
                last_sync_utc=_utc_now_z(),
            )
        except RuntimeError as exc:
            message = str(exc)
        except Exception as exc:
            message = f"同步异常: {exc}"

        with self._lock:
            self._status.update(
                {
                    "running": False,
                    "finished_at": _utc_now_z(),
                    "ok": ok,
                    "message": message,
                    "offset_ms": offset_ms,
                    "delay_ms": delay_ms,
                    "source_ip": target_ip,
                }
            )

    def _perform_sync(self, target_ip: str, port: int) -> _SampleResult | None:
        samples: list[_SampleResult] = []
        last_error: str | None = None
        for _ in range(self._samples):
            try:
                sample = self._single_exchange(target_ip, port)
                samples.append(sample)
            except RuntimeError as exc:
                last_error = str(exc)
                continue
        if not samples:
            if last_error:
                raise RuntimeError(last_error)
            return None
        # Choose the most stable sample by minimal RTT (monotonic).
        return min(samples, key=lambda item: item.rtt_ms)

    def _single_exchange(self, target_ip: str, port: int) -> _SampleResult:
        conn = HTTPConnection(target_ip, port, timeout=self._timeout_sec)
        t1 = time.time_ns()
        m1 = time.monotonic_ns()
        try:
            conn.request("GET", "/timesync")
            resp = conn.getresponse()
            body = resp.read()
        except TimeoutError as exc:
            raise RuntimeError("连接超时") from exc
        except ConnectionRefusedError as exc:
            raise RuntimeError("连接被拒绝") from exc
        except Exception as exc:
            raise RuntimeError(f"连接失败: {exc}") from exc
        finally:
            try:
                conn.close()
            except Exception:
                pass

        t4 = time.time_ns()
        m4 = time.monotonic_ns()

        if resp.status != 200:
            raise RuntimeError(f"非200状态码({resp.status})")

        try:
            payload = json.loads(body.decode("utf-8"))
        except Exception as exc:
            raise RuntimeError("JSON解析失败") from exc

        t2 = payload.get("t2")
        t3 = payload.get("t3")
        if t2 is None or t3 is None:
            raise RuntimeError("响应缺少t2/t3")
        try:
            t2_ns = int(t2)
            t3_ns = int(t3)
        except Exception as exc:
            raise RuntimeError("t2/t3格式无效") from exc

        offset_ns = 0.5 * ((t2_ns - t1) + (t3_ns - t4))
        delay_ns = (t4 - t1) - (t3_ns - t2_ns)
        rtt_ms = max(0.0, (m4 - m1) / 1_000_000.0)
        return _SampleResult(
            offset_ms=offset_ns / 1_000_000.0,
            delay_ms=delay_ns / 1_000_000.0,
            rtt_ms=rtt_ms,
        )


TIME_SERVICE_MANAGER = TimeServiceManager()
TIME_SYNC_MANAGER = TimeSyncManager()
