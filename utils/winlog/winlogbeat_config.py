"""用于主机日志采集的 Winlogbeat 配置生成器。"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable


DEFAULT_SECURITY_EVENT_IDS = [
    "4624",
    "4634",
    "4647",
    "4625",
    "4688",
    "4697",
    "4720",
    "4728",
    "4732",
    "4756",
    "1102",
]
DEFAULT_SYSTEM_EVENT_IDS = [
    "7045",
]


def _format_event_ids(event_ids: Iterable[str]) -> str:
    return ", ".join(str(item) for item in event_ids)


def generate_winlogbeat_config(
    output_dir: str | Path = "winlogbeat_output",
    *,
    include_xml: bool = False,
    batch_read_size: int = 512,
    security_event_ids: list[str] | None = None,
    system_event_ids: list[str] | None = None,
    file_prefix: str = "winlogbeat",
) -> str:
    """生成 winlogbeat.yml 配置文本。

    Args:
        output_dir: output.file 写入 NDJSON 的目录。
        include_xml: 是否包含 XML 原文。
        batch_read_size: Winlogbeat 读取批量大小（默认 512）。
        security_event_ids: 覆盖 Security 日志事件 ID 过滤列表。
        system_event_ids: 覆盖 System 日志事件 ID 过滤列表。
        file_prefix: output.file 输出文件前缀。

    Returns:
        YAML 配置文本字符串。
    """
    security_ids = security_event_ids or DEFAULT_SECURITY_EVENT_IDS
    system_ids = system_event_ids or DEFAULT_SYSTEM_EVENT_IDS

    include_xml_text = "true" if include_xml else "false"
    output_path = Path(output_dir).as_posix()

    config = (
        "winlogbeat.event_logs:\n"
        "  - name: Security\n"
        f"    event_id: [{_format_event_ids(security_ids)}]\n"
        f"    include_xml: {include_xml_text}\n"
        f"    batch_read_size: {batch_read_size}\n"
        "  - name: System\n"
        f"    event_id: [{_format_event_ids(system_ids)}]\n"
        f"    include_xml: {include_xml_text}\n"
        f"    batch_read_size: {batch_read_size}\n"
        "\n"
        "output.file:\n"
        f"  path: \"{output_path}\"\n"
        f"  filename: \"{file_prefix}\"\n"
        "  rotate_every_kb: 10240\n"
        "  number_of_files: 7\n"
    )
    return config


if __name__ == "__main__":
    import argparse
    import json
    from pathlib import Path as _Path

    from .parser_winlogbeat import extract_host_logs_from_winlogbeat_ndjson
    from .session_rebuild import rebuild_logon_sessions

    parser = argparse.ArgumentParser(description="生成 winlogbeat 配置并运行示例。")
    parser.add_argument("--output-dir", default="winlogbeat_output")
    parser.add_argument("--include-xml", action="store_true")
    parser.add_argument("--ndjson", default="sample_winlogbeat.ndjson")
    args = parser.parse_args()

    print(generate_winlogbeat_config(output_dir=args.output_dir, include_xml=args.include_xml))

    ndjson_path = _Path(args.ndjson)
    if ndjson_path.exists():
        events = extract_host_logs_from_winlogbeat_ndjson(ndjson_path, strict=False)
        print(json.dumps(events[:3], indent=2))
        sessions = rebuild_logon_sessions(events, strict=False)
        print(json.dumps({"session_count": len(sessions)}, indent=2))
    else:
        print(f"未找到示例 NDJSON 文件: {ndjson_path}")
