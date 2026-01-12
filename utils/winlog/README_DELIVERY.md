# Winlog 交付物

该目录包含主机日志采集与分析的交付物：

- winlogbeat.yml：Winlogbeat 文件输出配置。
- parser_winlogbeat.py：NDJSON 解析与归一化模块。
- session_rebuild.py：登录会话重建模块。
- winlogbeat_config.py：配置生成器。
- __init__.py：包导出入口。

## 示例

在任一模块下运行本地示例（需准备 NDJSON 文件）：

```bash
python -m utils.winlog.parser_winlogbeat sample_winlogbeat.ndjson
python -m utils.winlog.session_rebuild sample_winlogbeat.ndjson
```
