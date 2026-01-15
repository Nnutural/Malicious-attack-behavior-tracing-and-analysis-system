"""
在线抓包（可启停）：
- AsyncSniffer 捕获
- 解析后丢入队列
- 后台线程批量写入 SQL Server（按时间 flush）
"""
from __future__ import annotations

import json
import logging
import queue
import threading
import time
from dataclasses import dataclass
from typing import Any

from scapy.all import AsyncSniffer

from utils.traffic_fenxi.parser import PcapParser
from utils.traffic_fenxi.ingest_stream import NetworkTrafficStreamIngestor

logger = logging.getLogger(__name__)


@dataclass
class LiveCaptureConfig:
    iface: str
    bpf: str | None = None
    enable_analysis: bool = True
    flush_interval_sec: float = 1.0
    max_queue_size: int = 20000
    host_name: str | None = None
    content_meta: dict[str, Any] | None = None


class LiveCaptureHandle:
    """
    一个可控的在线抓包句柄：start 后运行，stop 后停止。
    用于 Flask 蓝图全局单例管理。
    """

    def __init__(self, cfg: LiveCaptureConfig, conn_str: str | None = None):
        self.cfg = cfg
        self.conn_str = conn_str

        self.q: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=cfg.max_queue_size)
        self.stop_event = threading.Event()
        self._dropped = 0
        self._started_at = time.time()

        self._parser = PcapParser(pcap_file="__live__")
        self._ingestor = NetworkTrafficStreamIngestor(
            conn_str=conn_str,
            enable_analysis=cfg.enable_analysis,
            flush_interval_sec=cfg.flush_interval_sec,
            raw_content=json.dumps(cfg.content_meta or {}, ensure_ascii=False),
            host_name=cfg.host_name,
        )

        self._writer_thread = threading.Thread(
            target=self._ingestor.run_writer_loop,
            args=(self.q, self.stop_event),
            name="traffic-db-writer",
            daemon=True,
        )

        self._sniffer = AsyncSniffer(
            iface=cfg.iface,
            filter=cfg.bpf,
            prn=self._on_pkt,
            store=False,
        )

    def _on_pkt(self, pkt):
        try:
            parsed = self._parser.parse_packet(pkt)
            if not parsed:
                return
            try:
                self.q.put_nowait(parsed)
            except queue.Full:
                self._dropped += 1
        except Exception:
            logger.exception("Failed to parse packet")

    def start(self):
        self._writer_thread.start()
        self._sniffer.start()
        logger.info("Live capture started: iface=%s bpf=%s", self.cfg.iface, self.cfg.bpf)

    def stop(self):
        # 先停抓包，再停写库
        try:
            self._sniffer.stop()
        except Exception:
            pass

        self.stop_event.set()
        try:
            self._ingestor.flush_queue(self.q)
        except Exception:
            logger.exception("flush_queue failed")

        self._writer_thread.join(timeout=5)
        logger.info("Live capture stopped.")

    def status(self) -> dict[str, Any]:
        stats = self._ingestor.get_stats()
        return {
            "running": self._sniffer.running if hasattr(self._sniffer, "running") else False,
            "iface": self.cfg.iface,
            "bpf": self.cfg.bpf,
            "host_name": self.cfg.host_name,
            "enable_analysis": self.cfg.enable_analysis,
            "flush_interval_sec": self.cfg.flush_interval_sec,
            "started_at": self._started_at,
            "uptime_sec": int(time.time() - self._started_at),
            "counters": {
                "inserted": stats.get("inserted", 0),
                "skipped": stats.get("skipped", 0),
                "errors": stats.get("errors", 0),
                "dropped": self._dropped,
            },
        }