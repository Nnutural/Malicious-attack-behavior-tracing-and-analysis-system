"""Windows Event Log 系统内采集器。"""

from __future__ import annotations

import logging
import platform
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
import xml.etree.ElementTree as ET

from .state_store import StateStore


logger = logging.getLogger(__name__)

DEFAULT_CHANNELS = ["Security", "System"]


def _normalize_system_time(value: str | None) -> str | None:
    if not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    if "." in text:
        head, tail = text.split(".", 1)
        if "+" in tail:
            frac, offset = tail.split("+", 1)
            if len(frac) > 6:
                frac = frac[:6]
            text = f"{head}.{frac}+{offset}"
        elif "-" in tail:
            frac, offset = tail.split("-", 1)
            if len(frac) > 6:
                frac = frac[:6]
            text = f"{head}.{frac}-{offset}"
        else:
            frac = tail
            if len(frac) > 6:
                frac = frac[:6]
            text = f"{head}.{frac}"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _text_or_none(element: ET.Element | None) -> str | None:
    if element is None:
        return None
    return (element.text or "").strip() or None


def _parse_event_data(root: ET.Element) -> dict[str, Any]:
    data: dict[str, Any] = {}
    event_data = root.findall(".//{*}EventData/{*}Data")
    if not event_data:
        event_data = root.findall(".//{*}UserData//{*}Data")
    for index, elem in enumerate(event_data, start=1):
        name = elem.attrib.get("Name") or f"param{index}"
        data[name] = (elem.text or "").strip()
    return data


def _parse_event_xml(xml_text: str, *, include_xml: bool, channel_hint: str | None) -> dict[str, Any] | None:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        logger.warning("解析事件 XML 失败: %s", exc)
        return None

    system = root.find("./{*}System")
    if system is None:
        return None

    provider_elem = system.find("./{*}Provider")
    provider = provider_elem.attrib.get("Name") if provider_elem is not None else None
    event_id_text = _text_or_none(system.find("./{*}EventID"))
    record_id_text = _text_or_none(system.find("./{*}EventRecordID"))
    channel = _text_or_none(system.find("./{*}Channel")) or channel_hint
    computer_name = _text_or_none(system.find("./{*}Computer"))
    time_created = system.find("./{*}TimeCreated")
    system_time = None
    if time_created is not None:
        system_time = time_created.attrib.get("SystemTime")

    event_id = int(event_id_text) if event_id_text and event_id_text.isdigit() else None
    record_id = int(record_id_text) if record_id_text and record_id_text.isdigit() else None
    system_time_utc = _normalize_system_time(system_time)
    event_data = _parse_event_data(root)

    raw_event: dict[str, Any] = {
        "channel": channel,
        "event_id": event_id,
        "record_id": record_id,
        "provider": provider,
        "computer_name": computer_name,
        "system_time_utc": system_time_utc,
        "event_data": event_data,
    }
    if include_xml:
        raw_event["xml"] = xml_text
    return raw_event


def _build_xpath_query(event_ids: Iterable[str] | None, last_record_id: int | None) -> str:
    conditions = []
    if event_ids:
        event_id_expr = " or ".join(f"EventID={event_id}" for event_id in event_ids)
        conditions.append(f"({event_id_expr})")
    if last_record_id:
        conditions.append(f"EventRecordID>{last_record_id}")
    if not conditions:
        return "*"
    return f"*[System[{' and '.join(conditions)}]]"


def _split_wevtutil_events(output: str) -> list[str]:
    matches = re.findall(r"<Event[^>]*>.*?</Event>", output, flags=re.S)
    if matches:
        return matches
    try:
        root = ET.fromstring(output)
    except ET.ParseError:
        return []
    return [ET.tostring(elem, encoding="unicode") for elem in root.findall(".//{*}Event")]


def _parse_record_count(output: str) -> int | None:
    for line in output.splitlines():
        text = line.strip()
        lower = text.lower()
        if "recordcount" in lower or "记录数" in text or "记录计数" in text:
            match = re.search(r"(\d+)", text)
            if match:
                return int(match.group(1))
    return None


class WindowsEventCollector:
    """Windows Event Log 系统内采集器（pywin32 优先，wevtutil 备选）。"""

    def __init__(
        self,
        *,
        channels: Iterable[str] | None,
        event_ids: Iterable[str] | None,
        include_xml: bool = False,
        batch_size: int = 512,
        state_store: StateStore | None = None,
        prefer_latest: bool = True,
        use_pywin32: bool = True,
        use_wevtutil_fallback: bool = True,
    ) -> None:
        self.channels = list(channels) if channels else list(DEFAULT_CHANNELS)
        self.event_ids = sorted({str(item) for item in event_ids}) if event_ids else []
        self.include_xml = include_xml
        self.batch_size = batch_size
        self.state_store = state_store or StateStore()
        self.prefer_latest = prefer_latest
        self.use_pywin32 = use_pywin32
        self.use_wevtutil_fallback = use_wevtutil_fallback

        self._win32evtlog = None
        if use_pywin32:
            try:
                import win32evtlog  # type: ignore

                self._win32evtlog = win32evtlog
            except Exception as exc:
                logger.warning("pywin32 不可用，将使用 wevtutil: %s", exc)

    def get_bookmark(self, channel: str) -> dict[str, Any] | None:
        """读取指定通道的断点状态。"""
        return self.state_store.get(channel)

    def save_bookmark(self, channel: str, bookmark: dict[str, Any]) -> None:
        """保存指定通道的断点状态。"""
        self.state_store.set(channel, bookmark)
        self.state_store.flush()

    def collect(self, *, max_events: int, timeout_sec: int = 2) -> list[dict]:
        """采集 Windows 事件日志，返回 RawEvent 列表。"""
        if platform.system().lower() != "windows":
            raise NotImplementedError("Windows Event Log 采集仅支持 Windows 平台")

        counts = self.get_total_record_counts()
        if counts:
            total = sum(counts.values())
            per_channel = ", ".join(f"{name}={value}" for name, value in counts.items())
            logger.warning("可读取日志总数（通道统计）：%s", per_channel)
            logger.warning("可读取日志总数（合计）：%d", total)

        results: list[dict] = []
        for channel in self.channels:
            remaining = max_events - len(results)
            if remaining <= 0:
                break
            try:
                if self._win32evtlog is not None:
                    events = self._collect_pywin32(channel, remaining, timeout_sec)
                elif self.use_wevtutil_fallback:
                    events = self._collect_wevtutil(channel, remaining)
                else:
                    raise RuntimeError("未启用可用的 Windows Event Log 采集路径")
            except PermissionError:
                raise
            except Exception as exc:
                if self._win32evtlog is not None and self.use_wevtutil_fallback:
                    logger.warning("pywin32 采集失败，切换到 wevtutil: %s", exc)
                    events = self._collect_wevtutil(channel, remaining)
                else:
                    raise
            results.extend(events)
        return results

    def _collect_pywin32(self, channel: str, max_events: int, timeout_sec: int) -> list[dict]:
        win32evtlog = self._win32evtlog
        if win32evtlog is None:
            return []

        state = self.get_bookmark(channel) or {}
        last_record_id = int(state.get("last_record_id", 0) or 0)
        query = _build_xpath_query(self.event_ids, last_record_id if last_record_id > 0 else None)
        flags = win32evtlog.EvtQueryChannelPath
        if self.prefer_latest and hasattr(win32evtlog, "EvtQueryReverseDirection"):
            flags |= win32evtlog.EvtQueryReverseDirection

        handle = win32evtlog.EvtQuery(channel, flags, query)
        collected: list[dict] = []
        latest_record_id = last_record_id

        while len(collected) < max_events:
            batch_size = min(self.batch_size, max_events - len(collected))
            handles = win32evtlog.EvtNext(handle, batch_size)
            if not handles:
                break
            for evt_handle in handles:
                xml_text = win32evtlog.EvtRender(evt_handle, win32evtlog.EvtRenderEventXml)
                raw_event = _parse_event_xml(xml_text, include_xml=self.include_xml, channel_hint=channel)
                if not raw_event:
                    continue
                if self.event_ids and str(raw_event.get("event_id")) not in self.event_ids:
                    continue
                raw_event["ingest_time_utc"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                collected.append(raw_event)
                if raw_event.get("record_id") is not None:
                    latest_record_id = max(latest_record_id, int(raw_event["record_id"]))

        if latest_record_id > last_record_id:
            self.save_bookmark(channel, {"last_record_id": latest_record_id})
        return collected

    def _collect_wevtutil(self, channel: str, max_events: int) -> list[dict]:
        state = self.get_bookmark(channel) or {}
        last_record_id = int(state.get("last_record_id", 0) or 0)

        state_dir = self.state_store.path.parent
        bookmark_path = state_dir / f"{channel}.bookmark.xml"
        read_direction = "/rd:true" if self.prefer_latest else "/rd:false"
        command = ["wevtutil", "qe", channel, "/f:xml", f"/c:{max_events}", read_direction]

        if self.prefer_latest:
            if self.event_ids or last_record_id:
                query = _build_xpath_query(self.event_ids, last_record_id if last_record_id > 0 else None)
                command.append(f"/q:{query}")
        else:
            if bookmark_path.exists():
                command.append(f"/bm:{bookmark_path}")
                command.append(f"/sbm:{bookmark_path}")
            elif self.event_ids or last_record_id:
                query = _build_xpath_query(self.event_ids, last_record_id if last_record_id > 0 else None)
                command.append(f"/q:{query}")

        try:
            output = subprocess.check_output(command, text=True, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as exc:
            message = (exc.stdout or "").strip()
            if "Access is denied" in message or "拒绝访问" in message:
                raise PermissionError(
                    f"读取 {channel} 日志被拒绝，请使用管理员权限或加入 Event Log Readers 组"
                ) from exc
            raise RuntimeError(f"wevtutil 读取失败: {message}") from exc

        events_xml = _split_wevtutil_events(output)
        collected: list[dict] = []
        latest_record_id = last_record_id

        for xml_text in events_xml:
            raw_event = _parse_event_xml(xml_text, include_xml=self.include_xml, channel_hint=channel)
            if not raw_event:
                continue
            if self.event_ids and str(raw_event.get("event_id")) not in self.event_ids:
                continue
            raw_event["ingest_time_utc"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            collected.append(raw_event)
            if raw_event.get("record_id") is not None:
                latest_record_id = max(latest_record_id, int(raw_event["record_id"]))

        if latest_record_id > last_record_id:
            self.save_bookmark(channel, {"last_record_id": latest_record_id, "bookmark_path": str(bookmark_path)})
        return collected

    def get_total_record_counts(self) -> dict[str, int]:
        """获取各通道可读取日志数量（通道总记录数）。"""
        counts: dict[str, int] = {}
        for channel in self.channels:
            count = self._get_wevtutil_record_count(channel)
            if count is not None:
                counts[channel] = count
        return counts

    def _get_wevtutil_record_count(self, channel: str) -> int | None:
        command = ["wevtutil", "gli", channel]
        try:
            output = subprocess.check_output(command, text=True, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as exc:
            message = (exc.stdout or "").strip()
            if "Access is denied" in message or "拒绝访问" in message:
                logger.warning("读取 %s 日志统计被拒绝，请使用管理员权限或加入 Event Log Readers 组", channel)
                return None
            logger.warning("wevtutil gli 失败: %s", message)
            return None
        return _parse_record_count(output)
