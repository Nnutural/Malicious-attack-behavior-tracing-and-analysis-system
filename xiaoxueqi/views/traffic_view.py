"""
网络流量分析视图
- 在线抓包 start/stop/status
- 离线上传 pcap/pcapng 导入入库
- 最近流量列表/详情
"""
from __future__ import annotations

import os
import time
import json
import threading
from pathlib import Path

from flask import Blueprint, current_app, jsonify, render_template, request

from config import Config
from utils.traffic_fenxi.parser import PcapParser
from utils.traffic_fenxi.ingest_offline import ingest_pcap_to_database
from utils.traffic_fenxi.live_capture import LiveCaptureConfig, LiveCaptureHandle
from utils.traffic_fenxi.storage_sqlserver import (
    count_networktraffic,
    get_networktraffic_by_id,
    list_networktraffic,
    parse_result_json,
)

bp = Blueprint("traffic", __name__)

# 全局单例（最小实现：同一时间只允许一个 live capture）
_LIVE_LOCK = threading.Lock()
_LIVE_HANDLE: LiveCaptureHandle | None = None


def _get_conn_str() -> str:
    # 目前你的项目 logs 支持切 DB server；traffic 暂时先用 Config
    # 后续如果你也要支持“页面设置 DB server”，再改为 session 取值即可
    return Config.SQL_CONN_STR


@bp.route("/", methods=["GET"])
def index():
    return render_template("traffic.html")


@bp.route("/api/live/status", methods=["GET"])
def api_live_status():
    global _LIVE_HANDLE
    with _LIVE_LOCK:
        if _LIVE_HANDLE is None:
            return jsonify(
                {
                    "ok": True,
                    "running": False,
                    "started_at": None,
                    "uptime_sec": 0,
                    "iface": None,
                    "bpf": None,
                    "host_name": None,
                    "counters": {"inserted": 0, "skipped": 0, "errors": 0, "dropped": 0},
                }
            )
        st = _LIVE_HANDLE.status()
        return jsonify({"ok": True, **st})


@bp.route("/api/live/start", methods=["POST"])
def api_live_start():
    """
    body:
    {
      "iface": "\\Device\\NPF_{...}",
      "bpf": "net 192.168.86.0/24",
      "flush_interval_sec": 1.0,
      "enable_analysis": true,
      "host_name": "VMnet1"
    }
    """
    global _LIVE_HANDLE

    payload = request.get_json(silent=True) or {}
    iface = (payload.get("iface") or "").strip()
    bpf = (payload.get("bpf") or "").strip() or None
    host_name = (payload.get("host_name") or "").strip() or None

    if not iface:
        return jsonify({"ok": False, "error": "iface required"}), 400

    flush_interval_sec = payload.get("flush_interval_sec", 1.0)
    try:
        flush_interval_sec = float(flush_interval_sec)
    except Exception:
        flush_interval_sec = 1.0

    enable_analysis = bool(payload.get("enable_analysis", True))

    with _LIVE_LOCK:
        if _LIVE_HANDLE is not None:
            st = _LIVE_HANDLE.status()
            if st.get("running"):
                return jsonify({"ok": False, "error": "live capture already running"}), 400

        cfg = LiveCaptureConfig(
            iface=iface,
            bpf=bpf,
            enable_analysis=enable_analysis,
            flush_interval_sec=flush_interval_sec,
            host_name=host_name or iface,  # 默认用 iface 当采集点标识
            content_meta={
                "capture_type": "live",
                "iface": iface,
                "bpf": bpf,
                "flush_interval_sec": flush_interval_sec,
                "host_name": host_name or iface,
            },
        )
        _LIVE_HANDLE = LiveCaptureHandle(cfg, conn_str=_get_conn_str())
        _LIVE_HANDLE.start()

        return jsonify({"ok": True, "message": "started", "status": _LIVE_HANDLE.status()})


@bp.route("/api/live/stop", methods=["POST"])
def api_live_stop():
    global _LIVE_HANDLE
    with _LIVE_LOCK:
        if _LIVE_HANDLE is None:
            return jsonify({"ok": True, "message": "already stopped"})

        try:
            _LIVE_HANDLE.stop()
        finally:
            _LIVE_HANDLE = None

    return jsonify({"ok": True, "message": "stopped"})


@bp.route("/api/upload", methods=["POST"])
def api_upload():
    """
    multipart/form-data:
    - file: pcap/pcapng
    - host_name: optional
    - enable_analysis: optional ("1"/"0")
    """
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


@bp.route("/api/recent", methods=["GET"])
def api_recent():
    host_name = (request.args.get("host_name") or "").strip() or None
    page = request.args.get("page", 1, type=int)
    page = max(page, 1)
    page_size = request.args.get("page_size", 20, type=int)
    page_size = max(5, min(page_size, 100))
    offset = (page - 1) * page_size

    conn_str = _get_conn_str()
    total = 0
    try:
        total = count_networktraffic(host_name=host_name, conn_str=conn_str)
    except Exception:
        total = 0

    rows = list_networktraffic(offset=offset, limit=page_size, host_name=host_name, conn_str=conn_str)

    items = []
    for r in rows:
        ev = parse_result_json(r.result)
        items.append(
            {
                "id": r.id,
                "create_time": str(r.create_time or ""),
                "host_name": r.host_name,
                "timestamp": str(ev.get("timestamp") or ""),
                "src_ip": ev.get("src_ip"),
                "dst_ip": ev.get("dst_ip"),
                "protocol": ev.get("protocol"),
                "event_type": ev.get("event_type"),
                "description": ev.get("description") or "",
            }
        )

    return jsonify({"ok": True, "total": total, "page": page, "page_size": page_size, "items": items})


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
                "result_raw": row.result,
            },
        }
    )