"""Windows 事件日志断点续读状态存储。"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)

DEFAULT_STATE_PATH = Path(__file__).resolve().parent / ".state" / "winevent_state.json"


class StateStore:
    """基于 JSON 文件的断点续读状态存储。"""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else DEFAULT_STATE_PATH
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._state: dict[str, Any] = {}
        self._dirty = False
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("状态文件读取失败: %s", exc)
            return
        if isinstance(data, dict):
            self._state = data

    def get(self, channel: str) -> dict[str, Any] | None:
        """获取指定通道的断点状态。"""
        value = self._state.get(channel)
        if value is None:
            return None
        if isinstance(value, dict):
            return dict(value)
        return None

    def set(self, channel: str, state: dict[str, Any]) -> None:
        """设置指定通道的断点状态。"""
        if not isinstance(state, dict):
            raise ValueError("state 必须为 dict")
        self._state[channel] = state
        self._dirty = True

    def flush(self) -> None:
        """将状态写入磁盘。"""
        if not self._dirty:
            return
        self.path.write_text(json.dumps(self._state, ensure_ascii=False, indent=2), encoding="utf-8")
        self._dirty = False
