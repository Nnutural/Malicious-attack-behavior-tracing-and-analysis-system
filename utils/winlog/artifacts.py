"""导出主机日志分析交付物。"""

from __future__ import annotations

import logging
import shutil
from pathlib import Path

from utils.winlog.legacy.winlogbeat_config import generate_winlogbeat_config, generate_windows_collector_config


logger = logging.getLogger(__name__)


def _default_readme() -> str:
    return (
        "# Winlog 交付物\n\n"
        "系统运行不依赖 Winlogbeat。该目录包含主机日志采集与分析的交付物：\n\n"
        "- windows_collector_config.yml：系统内采集器配置模板（推荐路径）。\n"
        "- winlogbeat.yml：Winlogbeat 参考配置（仅用于对照/报告）。\n"
        "- collector_windows.py：Windows Event Log 采集器。\n"
        "- state_store.py：断点续读状态存储。\n"
        "- parser_winlogbeat.py：日志解析与归一化模块（兼容 NDJSON）。\n"
        "- session_rebuild.py：登录会话重建模块。\n"
        "- winlogbeat_config.py：配置生成器。\n"
        "- __init__.py：包导出入口。\n\n"
        "运行方式：\n"
        "- 系统内采集（Windows）：调用 extract_host_logs_from_windows_eventlog。\n"
        "- 兼容输入（NDJSON）：调用 extract_host_logs_from_winlogbeat_ndjson。\n"
        "如读取 Security 通道被拒绝，请使用管理员权限或加入 Event Log Readers 组。\n"
    )


def _safe_write(path: Path, content: str, overwrite: bool) -> None:
    if path.exists() and not overwrite:
        raise FileExistsError(f"{path} 已存在；将 overwrite=True 以覆盖")
    path.write_text(content, encoding="utf-8")


def _safe_copy(src: Path, dest: Path, overwrite: bool) -> None:
    if dest.exists() and not overwrite:
        raise FileExistsError(f"{dest} 已存在；将 overwrite=True 以覆盖")
    shutil.copy2(src, dest)


def export_winlog_deliverables(out_dir: str | Path, *, overwrite: bool = False) -> dict:
    """导出采集与分析模块到交付目录。

    Args:
        out_dir: 交付物输出目录。
        overwrite: 是否覆盖已有文件。

    Returns:
        包含 ok、out_dir、files 的结果字典。
    """
    output_path = Path(out_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    files: list[str] = []

    collector_config_text = generate_windows_collector_config()
    collector_config_path = output_path / "windows_collector_config.yml"
    _safe_write(collector_config_path, collector_config_text, overwrite)
    files.append(str(collector_config_path))

    winlogbeat_config_text = generate_winlogbeat_config()
    winlogbeat_config_path = output_path / "winlogbeat.yml"
    _safe_write(winlogbeat_config_path, winlogbeat_config_text, overwrite)
    files.append(str(winlogbeat_config_path))

    module_dir = Path(__file__).resolve().parent
    for name in [
        "collector_windows.py",
        "state_store.py",
        "parser_winlogbeat.py",
        "session_rebuild.py",
        "winlogbeat_config.py",
        "__init__.py",
        "README_DELIVERY.md",
    ]:
        src = module_dir / name
        dest = output_path / name
        if src.exists():
            _safe_copy(src, dest, overwrite)
            files.append(str(dest))
        elif name == "README_DELIVERY.md":
            _safe_write(dest, _default_readme(), overwrite)
            files.append(str(dest))
        else:
            logger.warning("缺少交付物源文件: %s", src)

    return {"ok": True, "out_dir": str(output_path), "files": files}


if __name__ == "__main__":
    import argparse
    import json

    from .parser_winlogbeat import extract_host_logs_from_winlogbeat_ndjson
    from .session_rebuild import rebuild_logon_sessions

    parser = argparse.ArgumentParser(description="导出交付物示例。")
    parser.add_argument("out_dir", nargs="?", default="deliverables")
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--ndjson", default="sample_winlogbeat.ndjson")
    args = parser.parse_args()

    result = export_winlog_deliverables(args.out_dir, overwrite=args.overwrite)
    print(json.dumps(result, indent=2))

    ndjson_path = Path(args.ndjson)
    if ndjson_path.exists():
        events = extract_host_logs_from_winlogbeat_ndjson(ndjson_path, strict=False)
        print(json.dumps(events[:3], indent=2))
        sessions = rebuild_logon_sessions(events, strict=False)
        print(json.dumps({"session_count": len(sessions)}, indent=2))
    else:
        print(f"未找到示例 NDJSON 文件: {ndjson_path}")
