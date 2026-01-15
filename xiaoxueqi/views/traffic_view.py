"""
网络流量分析视图（dumpcap 稳定版）
- 在线抓包：dumpcap 子进程写 pcapng
- 停止抓包：读取 pcapng -> 解析 -> 入库
- 避免 scapy AsyncSniffer 导致 Python 进程崩溃
"""
from __future__ import annotations

import os
import time
import threading
import json
from pathlib import Path

from flask import Blueprint, current_app, jsonify, render_template, request, abort, url_for

from config import Config
from utils.traffic_fenxi.parser import PcapParser
from utils.traffic_fenxi.ingest_offline import ingest_pcap_to_database
from utils.traffic_fenxi.live_capture_dumpcap import DumpcapCaptureConfig, DumpcapCaptureHandle
from utils.traffic_fenxi.storage_sqlserver import (
    get_networktraffic_by_id,
    list_networktraffic,
    parse_result_json,
)

bp = Blueprint("traffic", __name__)

PAGE_SIZE = 20


def _get_conn_str() -> str:
    return Config.SQL_CONN_STR


# =========================
# 全局 Live Capture 管理（dumpcap handle）
# =========================
class _TrafficCaptureManager:
    def __init__(self):
        self.lock = threading.Lock()
        self.handle: DumpcapCaptureHandle | None = None
        self.last_error: str | None = None
        self.last_error_time: float | None = None
        self.last_capture_file: str | None = None
        self.last_import: dict | None = None


def _mgr() -> _TrafficCaptureManager:
    mgr = current_app.extensions.get("traffic_capture_manager")
    if mgr is None:
        mgr = _TrafficCaptureManager()
        current_app.extensions["traffic_capture_manager"] = mgr
    return mgr


# =========================
# event_type 筛选
# =========================
def _event_type_options() -> list[dict[str, str]]:
    return [
        {"value": "", "label": "全部"},
        {"value": "__alert__", "label": "仅告警（suspected）"},
        {"value": "dns_tunnel_suspected", "label": "DNS 隧道（suspected）"},
        {"value": "http_tunnel_suspected", "label": "HTTP 隧道（suspected）"},
        {"value": "icmp_tunnel_suspected", "label": "ICMP 隧道（suspected）"},
        {"value": "dns_query", "label": "DNS 查询（dns_query）"},
        {"value": "tcp_connection", "label": "TCP 连接（tcp_connection）"},
    ]


def _filter_match_event_type(event_type_value: str, item_event_type: str) -> bool:
    if not event_type_value:
        return True
    if event_type_value == "__alert__":
        return "suspected" in (item_event_type or "")
    return (item_event_type or "") == event_type_value


def _row_to_list_item(r) -> dict:
    ev = parse_result_json(r.result)
    return {
        "id": r.id,
        "create_time": str(r.create_time or ""),
        "timestamp": str(ev.get("timestamp") or ""),
        "src_ip": ev.get("src_ip") or "",
        "dst_ip": ev.get("dst_ip") or "",
        "protocol": ev.get("protocol") or "",
        "event_type": ev.get("event_type") or "",
        "description": (ev.get("description") or ""),
    }


@bp.route("/", methods=["GET"])
def index():
    page = request.args.get("page", 1, type=int)
    page = max(page, 1)
    event_type = (request.args.get("event_type") or "").strip()

    items: list[dict] = []
    total = 0
    total_pages = 1

    try:
        scan_limit = 2000
        rows = list_networktraffic(offset=0, limit=scan_limit, host_name=None, conn_str=_get_conn_str())
        all_items = [_row_to_list_item(r) for r in rows]
        filtered = [it for it in all_items if _filter_match_event_type(event_type, it.get("event_type") or "")]

        total = len(filtered)
        total_pages = max((total + PAGE_SIZE - 1) // PAGE_SIZE, 1)
        if page > total_pages:
            page = total_pages

        start = (page - 1) * PAGE_SIZE
        items = filtered[start : start + PAGE_SIZE]
    except Exception:
        items = []
        total = 0
        total_pages = 1

    mgr = _mgr()
    with mgr.lock:
        live_status = mgr.handle.status() if mgr.handle else {"running": False}
        last_capture_file = mgr.last_capture_file
        last_import = mgr.last_import
        last_error = mgr.last_error

    return render_template(
        "traffic.html",
        items=items,
        page=page,
        total=total,
        total_pages=total_pages,
        page_size=PAGE_SIZE,
        event_type=event_type,
        event_type_options=_event_type_options(),
        live_status=live_status,
        last_capture_file=last_capture_file,
        last_import=last_import,
        last_error=last_error,
    )


# =========================
# Live capture APIs（dumpcap）
# =========================
@bp.route("/api/live/status", methods=["GET"])
def api_live_status():
    mgr = _mgr()
    with mgr.lock:
        st = mgr.handle.status() if mgr.handle else {"running": False, "iface": None, "bpf": None, "pcap_file": None, "uptime_sec": 0}
        return jsonify(
            {
                "ok": True,
                **st,
                "last_error": mgr.last_error,
                "last_error_time": mgr.last_error_time,
                "last_capture_file": mgr.last_capture_file,
                "last_import": mgr.last_import,
            }
        )


@bp.route("/api/live/start", methods=["POST"])
def api_live_start():
    payload = request.get_json(silent=True) or {}
    iface = (payload.get("iface") or "").strip()
    bpf = (payload.get("bpf") or "").strip() or None
    host_name = (payload.get("host_name") or "").strip() or None
    dumpcap_path = (payload.get("dumpcap_path") or "").strip() or Config.DUMPCAP_PATH

    if not iface:
        return jsonify({"ok": False, "error": "iface required"}), 400

    mgr = _mgr()
    with mgr.lock:
        try:
            if mgr.handle and mgr.handle.is_running():
                return jsonify({"ok": False, "error": "live capture already running"}), 400

            cfg = DumpcapCaptureConfig(
                iface=iface,
                bpf=bpf,
                dumpcap_path=dumpcap_path,
                output_dir=Config.LIVE_CAPTURE_DIR,
                host_name=host_name or iface,
            )
            mgr.handle = DumpcapCaptureHandle(cfg)
            info = mgr.handle.start()

            mgr.last_error = None
            mgr.last_error_time = None
            mgr.last_capture_file = mgr.handle.pcap_file
            mgr.last_import = None

            return jsonify({"ok": True, "message": "started", "capture": info, "status": mgr.handle.status()})
        except Exception as exc:
            mgr.last_error = f"live start failed: {exc}"
            mgr.last_error_time = time.time()
            mgr.handle = None
            return jsonify({"ok": False, "error": str(exc)}), 500


@bp.route("/api/live/stop", methods=["POST"])
def api_live_stop():
    """
    stop 后会自动导入入库（离线解析）
    body 可选：
    {
      "enable_analysis": true,
      "host_name": "VMnet1"
    }
    """
    payload = request.get_json(silent=True) or {}
    enable_analysis = bool(payload.get("enable_analysis", True))
    host_name = (payload.get("host_name") or "").strip() or None

    mgr = _mgr()
    with mgr.lock:
        if not mgr.handle:
            return jsonify({"ok": True, "message": "already stopped", "import": mgr.last_import})

        handle = mgr.handle
        mgr.handle = None

    # stop & import 放到锁外，避免卡住其他请求
    try:
        stop_info = handle.stop()
        pcap_file = stop_info.get("pcap_file") or handle.pcap_file
        if not pcap_file or not os.path.exists(pcap_file):
            raise RuntimeError(f"capture file missing: {pcap_file}")

        parser = PcapParser(pcap_file)
        if not parser.load():
            raise RuntimeError("failed to read captured pcap")

        parsed_packets = parser.parse_all()
        raw_content = parser.get_raw_content()

        import_result = ingest_pcap_to_database(
            parsed_packets=parsed_packets,
            raw_content=raw_content,
            conn_str=_get_conn_str(),
            enable_analysis=enable_analysis,
            host_name=host_name or (handle.cfg.host_name or "live_capture"),
        )

        with mgr.lock:
            mgr.last_capture_file = pcap_file
            mgr.last_import = import_result
            mgr.last_error = None
            mgr.last_error_time = None

        return jsonify({"ok": True, "message": "stopped_and_imported", "pcap_file": pcap_file, "import": import_result})
    except Exception as exc:
        with mgr.lock:
            mgr.last_error = f"live stop/import failed: {exc}"
            mgr.last_error_time = time.time()
        return jsonify({"ok": False, "error": str(exc)}), 500


# =========================
# Offline upload
# =========================
@bp.route("/api/upload", methods=["POST"])
def api_upload():
    if "file" not in request.files:
        return jsonify({"ok": False, "error": "file required"}), 400

    f = request.files["file"]
    if not f or not f.filename:
        return jsonify({"ok": False, "error": "invalid file"}), 400

    host_name = (request.form.get("host_name") or "").strip() or None
    enable_analysis = (request.form.get("enable_analysis") or "").strip() not in ("0", "false", "False")

    filename = f.filename
    ext = Path(filename).suffix.lower()
    if ext not in (".pcap", ".pcapng", ".cap"):
        return jsonify({"ok": False, "error": "only .pcap/.pcapng/.cap supported"}), 400

    upload_dir = current_app.config.get("UPLOAD_FOLDER") or Config.UPLOAD_FOLDER
    os.makedirs(upload_dir, exist_ok=True)

    saved_path = os.path.join(upload_dir, f"{int(time.time())}_{filename}")
    f.save(saved_path)

    parser = PcapParser(saved_path)
    if not parser.load():
        return jsonify({"ok": False, "error": "failed to read pcap"}), 500

    parsed_packets = parser.parse_all()
    raw_content = parser.get_raw_content()

    result = ingest_pcap_to_database(
        parsed_packets=parsed_packets,
        raw_content=raw_content,
        conn_str=_get_conn_str(),
        enable_analysis=enable_analysis,
        host_name=host_name or filename,
    )
    return jsonify({"ok": True, "saved_path": saved_path, "result": result})


# =========================
# Detail APIs / pages（修正路由：必须带 traffic_id）
# =========================
@bp.route("/api/detail/<int:traffic_id>", methods=["GET"])
def api_detail(traffic_id: int):
    row = get_networktraffic_by_id(traffic_id, conn_str=_get_conn_str())
    if not row:
        return jsonify({"ok": False, "error": "not found"}), 404
    ev = parse_result_json(row.result)
    return jsonify(
        {
            "ok": True,
            "row": {
                "id": row.id,
                "create_time": str(row.create_time or ""),
                "event_hash": row.event_hash,
                "host_name": row.host_name,
                "event_time_utc": str(row.event_time_utc or ""),
                "result": ev,
                "content": row.content,
            },
        }
    )


@bp.route("/detail/<int:traffic_id>", methods=["GET"])
def detail_page(traffic_id: int):
    row = get_networktraffic_by_id(traffic_id, conn_str=_get_conn_str())
    if not row:
        abort(404)

    ev = parse_result_json(row.result) or {}
    pretty = json.dumps(ev, ensure_ascii=False, indent=2) if ev else (row.result or "")
    back_url = url_for("traffic.index", event_type=(request.args.get("event_type") or "").strip() or None)

    return render_template(
        "traffic_detail.html",
        traffic={
            "id": row.id,
            "create_time": str(row.create_time or ""),
            "event_hash": row.event_hash,
            "event_time_utc": str(row.event_time_utc or ""),
            "timestamp": str(ev.get("timestamp") or ""),
            "src_ip": ev.get("src_ip") or "",
            "dst_ip": ev.get("dst_ip") or "",
            "protocol": ev.get("protocol") or "",
            "event_type": ev.get("event_type") or "",
            "description": ev.get("description") or "",
            "result_json_pretty": pretty,
            "raw_content": row.content or "",
            "back_url": back_url,
        },
    )