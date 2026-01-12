"""导出主机日志分析交付物。"""

from __future__ import annotations

import logging
import shutil
from pathlib import Path

from .winlogbeat_config import generate_winlogbeat_config


logger = logging.getLogger(__name__)


def _default_readme() -> str:
    return (
        "# Winlog 交付物\n\n"
        "该目录包含主机日志采集与分析的交付物：\n\n"
        "- winlogbeat.yml：Winlogbeat 文件输出配置。\n"
        "- parser_winlogbeat.py：NDJSON 解析与归一化模块。\n"
        "- session_rebuild.py：登录会话重建模块。\n"
        "- winlogbeat_config.py：配置生成器。\n"
        "- __init__.py：包导出入口。\n"
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
    """导出 Winlogbeat 配置与分析模块到交付目录。

    Args:
        out_dir: 交付物输出目录。
        overwrite: 是否覆盖已有文件。

    Returns:
        包含 ok、out_dir、files 的结果字典。
    """
    output_path = Path(out_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    files: list[str] = []

    config_text = generate_winlogbeat_config()
    config_path = output_path / "winlogbeat.yml"
    _safe_write(config_path, config_text, overwrite)
    files.append(str(config_path))

    module_dir = Path(__file__).resolve().parent
    for name in [
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
