"""
在线抓包（dumpcap 子进程版，稳定）：
- start: 启动 dumpcap 抓包写 pcapng 文件
- stop: 停止 dumpcap，返回 capture_file_path
- status: 返回 running/elapsed/pcap_file 等

设计目标：
- 避免 scapy AsyncSniffer 导致 Python 进程崩溃
- 抓包期间不解析/不入库（更稳）
- stop 后由 Flask 调用离线解析入库（PcapParser + ingest_offline）
"""
from __future__ import annotations

import os
import signal
import subprocess
import time
from dataclasses import dataclass
from typing import Any


@dataclass
class DumpcapCaptureConfig:
    iface: str
    bpf: str | None = None
    dumpcap_path: str | None = None
    output_dir: str = "data/live_captures"
    host_name: str | None = None


class DumpcapCaptureHandle:
    def __init__(self, cfg: DumpcapCaptureConfig):
        self.cfg = cfg
        self._proc: subprocess.Popen | None = None
        self._started_at: float | None = None
        self._pcap_file: str | None = None
        self._last_error: str | None = None

    @property
    def pcap_file(self) -> str | None:
        return self._pcap_file

    @property
    def last_error(self) -> str | None:
        return self._last_error

    def start(self) -> dict[str, Any]:
        if self._proc and self._proc.poll() is None:
            return {"started": False, "message": "already running", "pcap_file": self._pcap_file}

        dumpcap = (self.cfg.dumpcap_path or "").strip()
        if not dumpcap:
            raise RuntimeError("dumpcap_path is empty")
        if not os.path.exists(dumpcap):
            raise RuntimeError(f"dumpcap not found: {dumpcap}")

        os.makedirs(self.cfg.output_dir, exist_ok=True)

        ts = time.strftime("%Y%m%d_%H%M%S")
        safe_host = (self.cfg.host_name or "live").replace(":", "_").replace("\\", "_").replace("/", "_")
        filename = f"live_{safe_host}_{ts}.pcapng"
        out_path = os.path.join(self.cfg.output_dir, filename)
        self._pcap_file = out_path

        # dumpcap 参数：
        # -i <iface>
        # -w <file>
        # -f <bpf> (可选)
        args = [dumpcap, "-i", self.cfg.iface, "-w", out_path]
        if self.cfg.bpf:
            args.extend(["-f", self.cfg.bpf])

        # 在 Windows 上不需要 shell=True，list 参数会正确处理空格路径
        # stdout/stderr 采集下来便于排错（不阻塞：用 PIPE）
        self._proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self._started_at = time.time()
        self._last_error = None

        return {"started": True, "pcap_file": out_path, "args": args}

    def stop(self, timeout_sec: float = 3.0) -> dict[str, Any]:
        if not self._proc:
            return {"stopped": True, "message": "not running", "pcap_file": self._pcap_file}

        proc = self._proc
        self._proc = None

        try:
            if proc.poll() is None:
                # 尝试温和终止
                proc.terminate()
                try:
                    proc.wait(timeout=timeout_sec)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=timeout_sec)
        finally:
            # 读取一下 stderr 方便定位
            err = ""
            try:
                if proc.stderr:
                    err = (proc.stderr.read() or "").strip()
            except Exception:
                err = ""
            if err:
                self._last_error = err[-2000:]  # 截断避免太长

        return {"stopped": True, "pcap_file": self._pcap_file, "stderr": self._last_error}

    def is_running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def status(self) -> dict[str, Any]:
        running = self.is_running()
        started_at = self._started_at
        uptime = int(time.time() - started_at) if (running and started_at) else 0
        return {
            "running": running,
            "iface": self.cfg.iface,
            "bpf": self.cfg.bpf,
            "pcap_file": self._pcap_file,
            "started_at": started_at,
            "uptime_sec": uptime,
            "last_error": self._last_error,
        }