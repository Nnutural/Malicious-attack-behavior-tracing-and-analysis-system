# Winlog 交付物

该目录包含主机日志采集与分析的交付物（系统运行不依赖 Winlogbeat）：

- windows_collector_config.yml：系统内采集器配置模板（推荐路径）。
- winlogbeat.yml：Winlogbeat 参考配置（仅用于对照/报告）。
- collector_windows.py：Windows Event Log 采集器（系统内采集）。
- state_store.py：断点续读状态存储。
- parser_winlogbeat.py：日志解析与归一化模块（兼容 NDJSON）。
- session_rebuild.py：登录会话重建模块。
- winlogbeat_config.py：配置生成器。
- __init__.py：包导出入口。

## 运行方式

系统内采集（推荐，Windows 平台）：

```bash
python -c "from utils.winlog import extract_host_logs_from_windows_eventlog as f; print(f(max_events=5))"
```

若读取 Security 通道被拒绝，请使用管理员权限运行，或将账户加入 Event Log Readers 组。

兼容输入（离线重放 NDJSON）：

```bash
python -c "from utils.winlog import extract_host_logs_from_winlogbeat_ndjson as f; print(f('sample_winlogbeat.ndjson', strict=False)[:3])"
```

#### 功能实现
时间序列对齐
实现位置：parser_winlogbeat.py
逻辑：
事件时间以 system_time_utc（系统采集）或 @timestamp（NDJSON）为事件发生时间；统一转为 UTC ISO8601（Z 结尾）。
支持 clock_offset_ms 进行固定偏移修正。
可选记录采集延迟（_ingest_delay_ms），但不改变事件语义时间。
日志范式解析
实现位置：parser_winlogbeat.py
逻辑：
统一输出结构：data_source/timestamp/host_ip/event_type/raw_id/entities/description
事件 ID → 归一化事件类型映射表（唯一真值来源）：
4624→user_logon，4634/4647→user_logoff，4625→user_logon_failed，4688→process_creation_log，7045/4697→service_install，4720→account_created，4728/4732/4756→group_membership_add，1102→log_clear
关键信息提取（用户/进程/文件/注册表）
实现位置：parser_winlogbeat.py 的实体抽取逻辑
逻辑：
用户：从 user.name 提取
源 IP：从 source.ip 提取
会话 ID：从 TargetLogonId/SubjectLogonId/LogonId 提取
进程（4688）：NewProcessName/NewProcessId/ParentProcessName/CommandLine
服务（7045/4697）：ServiceName/ImagePath
目前文件/注册表键值没有独立事件映射（Windows 需要开启对象访问审计/特定事件 ID 才能提供），因此只有当事件数据里存在相关字段时才会被带出。
缺失关键字段会记录 warning，但不会阻断输出。
登录会话重建
实现位置：session_rebuild.py
逻辑：
使用 (host_ip, session_id) 聚合
4624 打开会话，4634/4647 关闭会话
超过 session_timeout_sec 未关闭则标记 timeout
若同 session_id 出现时间倒退/冲突，切分为新会话

# TODO
## 1. 只能在本机运行 无法统一不同主机和设备的日志
如果需要不同主机上运行该部分，则应每个部分起码实现了该日志采集模块，另外也应是指不同的存储方式以区分

## 2. 限制了200条日志采集
而且日志日期存在问题

## 3. 读取数据库显示序号为从大到小

## 4. 数据较为重复无价值 如何提取重要的有威胁消息？

## 5. 数据存储并未加密

### 1/13

## 采集日志记录存在准确率不高的问题：体现在可能重复、恶意攻击价值不高等问题

## 数据库可能存在重复数据