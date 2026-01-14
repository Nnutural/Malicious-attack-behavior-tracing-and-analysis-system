# Winlog 交付物

本目录提供主机日志采集与分析的核心实现与交付物（系统运行不依赖 Winlogbeat）。下文从“模块职责、数据流、输入输出、数据库交互、展示与可视化”几个角度完整说明实现细节。

## 1. 模块结构与职责

- `collector_windows.py`：Windows Event Log 系统内采集器（pywin32 优先，wevtutil 兜底）。负责读取系统日志、解析 XML、生成 raw_event。
- `parser_winlogbeat.py`：日志解析与归一化模块。把 raw_event/NDJSON 转成统一范式事件（带 timestamp/event_type/entities 等）。
- `state_store.py`：断点续读状态存储（JSON 文件），用于记录事件读取进度。
- `session_rebuild.py`：登录会话重建模块。基于登录/注销事件重建会话时间线。
- `time_sync.py`：软同步时钟模块。提供 HTTP 时间服务（Leader）与客户端同步（Client），不修改系统时间，仅生成 offset。
- `service/hostlogs_ingest.py`：入库编排。调用采集器 + 解析器，追加时钟同步字段，去重后写入 SQL Server。
- `storage/hostlogs_sqlserver.py`：SQL Server 交互层（HostLogs 表）。
- `service/logontracer_service.py`：LogonTracer 聚合计算（图/时间线/会话）。
- `service/logontracer_jobs.py`：LogonTracer 后台任务管理（队列、进度、缓存）。
- `legacy/winlogbeat_config.py`：Winlogbeat 配置生成器（仅参考/对照）。
- `__init__.py`：对外导出接口。

## 2. 数据流概览

**系统内采集路径（推荐）**：
1) `collector_windows.py` 读取 Windows Event Log（Security/System）→ 生成 raw_event  
2) `parser_winlogbeat.py` 归一化事件 → 输出统一 JSON  
3) `service/hostlogs_ingest.py` 追加时钟字段/去重 → 写入 SQL Server `HostLogs`  
4) 前端日志页与 LogonTracer 模块读取 `HostLogs` 展示分析结果

**离线回放路径（兼容 NDJSON）**：
1) `parser_winlogbeat.py` 解析 Winlogbeat NDJSON  
2) 得到统一事件结构（供离线分析、测试与复现）

## 3. 主要输入输出

### 3.1 采集与解析

**输入：**  
- Windows Event Log（系统内）  
  `extract_host_logs_from_windows_eventlog(...)`  
- 或 Winlogbeat NDJSON（离线文件）  
  `extract_host_logs_from_winlogbeat_ndjson(path)`

**输出：**统一事件结构：
```json
{
  "data_source": "host_log",
  "timestamp": "2026-01-14T03:20:10Z",
  "host_ip": "DESKTOP-ABC",
  "event_type": "user_logon",
  "raw_id": "4624",
  "entities": {
    "user": "alice",
    "src_ip": "10.0.0.5",
    "session_id": "0x3e7"
  },
  "description": "事件类型=user_logon, 事件ID=4624, 用户=alice, 源IP=10.0.0.5, 会话ID=0x3e7"
}
```

**特殊字段：**当 `include_xml=True` 时，输出会额外带 `_raw_xml` 和 `_computer_name`（入库前会移除）。

### 3.2 登录会话重建

函数签名：
```python
def rebuild_logon_sessions(
    host_log_events: list[dict],
    *,
    session_timeout_sec: int = 8 * 3600,
    strict: bool = True,
) -> list[dict]:
    ...
```

返回示例：
```json
[
  {
    "host_ip": "DESKTOP-ABC",
    "session_id": "0x3e7",
    "user": "alice",
    "src_ip": "10.0.0.5",
    "start_time": "2026-01-14T03:20:10Z",
    "end_time": "2026-01-14T04:05:20Z",
    "events": 2,
    "status": "closed"
  }
]
```

### 3.3 入库输出

入库写入 `dbo.HostLogs.result` 为 JSON 字符串；同时增加时钟同步字段（见下文）。

## 4. 时间对齐与软同步（Soft Sync）

### 4.1 归一化阶段的时间对齐
位置：`parser_winlogbeat.py`  
逻辑：
- 将事件时间统一转换为 UTC (`Z` 结尾 ISO8601)。
- 支持 `clock_offset_ms` 固定偏移修正。
- 若 offset=0 且采集器提供 `ingest_time_utc`，会记录 `_ingest_delay_ms` 仅用于观测延迟。

### 4.2 软同步模块
位置：`time_sync.py`  
实现要点：
- Leader 启动 HTTP 服务 `/timesync`，返回 `t2/t3`（服务端接收/响应时间）。
- Client 用 RFC5905 四时间戳公式估算 offset：
  `offset = 0.5 * ((T2-T1) + (T3-T4))`
  `delay = (T4-T1) - (T3-T2)`
- 采样默认 10 次，选 RTT 最小样本。
- 结果写入 `.state/time_sync_state.json`（offset_ms、delay_ms、source_ip、last_sync_utc）。

### 4.3 入库时应用 offset
位置：`service/hostlogs_ingest.py`
- 在写入数据库前读取最近同步结果。
- 按 `offset_ms` 修正事件 `timestamp`。
- 同时写入以下字段到 `result` JSON：  
  `clock_offset_ms` / `clock_delay_ms` / `clock_source_ip` / `clock_sync_time_utc` / `clock_status`

## 5. 归一化与关键实体抽取

### 5.1 事件类型映射
位置：`parser_winlogbeat.py`  
映射表（核心事件）：
- 4624 → user_logon  
- 4634/4647 → user_logoff  
- 4625 → user_logon_failed  
- 4688 → process_creation_log  
- 7045/4697 → service_install  
- 4720 → account_created  
- 4728/4732/4756 → group_membership_add  
- 1102 → log_clear

### 5.2 关键字段抽取
位置：`parser_winlogbeat.py` 中 `_extract_entities`  
规则：
- 用户：`TargetUserName` / `SubjectUserName` / `user.name` / `user`
- 源 IP：`IpAddress` / `SourceNetworkAddress` / `ClientAddress` / `source.ip`
- 会话 ID：`TargetLogonId` / `SubjectLogonId` / `LogonId`
- 进程（4688）：`NewProcessName` / `NewProcessId` / `ParentProcessName` / `CommandLine`
- 服务（7045/4697）：`ServiceName` / `ImagePath`

缺失关键字段会记录 warning，不阻断输出。

## 6. 登录会话重建机制

位置：`session_rebuild.py`  
核心逻辑：
- 用 `(host_ip, session_id)` 聚合会话。
- 4624 打开会话，4634/4647 关闭会话。
- 若同 session_id 出现时间回退/重复，切分为新会话。
- 超过 `session_timeout_sec` 未关闭的会话标记为 `timeout`。

## 7. 数据库交互

### 7.1 HostLogs 表结构
```sql
id INT IDENTITY PRIMARY KEY
result NVARCHAR(MAX)
content NVARCHAR(MAX)
create_time DATETIME2 DEFAULT(sysdatetime())
event_hash VARCHAR(64) NULL
host_name NVARCHAR(255) NULL
```

### 7.2 入库流程
位置：`service/hostlogs_ingest.py`  
流程：
- 采集 Windows Event Log → 解析 → 生成 `result_json`  
- 计算 `event_hash` 去重（建议建唯一索引）  
- `content` 默认存 XML（无 XML 则存 Pretty JSON）  
- `host_name` 存 `ComputerName`  
- 插入到 `dbo.HostLogs`

建议索引：
```sql
CREATE UNIQUE INDEX UX_HostLogs_event_hash
ON dbo.HostLogs(event_hash)
WHERE event_hash IS NOT NULL;

CREATE INDEX IX_HostLogs_host_name
ON dbo.HostLogs(host_name);
```

## 8. 展示与可视化

### 8.1 日志页面
位置：`xiaoxueqi/views/log_view.py` + `templates/logs.html`  
展示内容：
- 按页展示 `HostLogs.result` 中的时间、主机、事件类型、描述  
- 支持 `host_name` 筛选  
- 日志详情页展示 `result` + 原始 `content`

### 8.2 LogonTracer 可视化
位置：`service/logontracer_service.py` / `service/logontracer_jobs.py`  
流程：
- 以 `create_time` 过滤（数据库层），再以 `timestamp` 二次过滤（事件层）
- 生成三类结果：
  1) **Graph**：`ip -> host` 与 `user -> host` 两类边  
  2) **Timeline**：成功/失败按 hour/day 聚合  
  3) **Sessions**：调用 `rebuild_logon_sessions`
- 结果由 `/api/logontracer/*` 提供给前端渲染

前端依赖（CDN）：
- Cytoscape.js（关系图）
- DataTables（会话表，server-side）
- Chart.js + Luxon adapter（时间线）

## 9. API 与线程任务

### 9.1 Time Sync（软同步）
- `/timesync`：Leader 时间响应（t2/t3）
- `/logs/time_sync/*`：前端控制入口（启动服务/启动同步/查询状态）

### 9.2 LogonTracer
- `POST /api/logontracer/start` → 返回 `job_id`
- `GET /api/logontracer/job/<job_id>` → 任务状态
- `GET /api/logontracer/graph?job_id=...`
- `GET /api/logontracer/timeline?job_id=...`
- `GET /api/logontracer/sessions?job_id=...`（DataTables）
- `GET /api/logontracer/session_events?...`

## 10. 运行方式（常用）

系统内采集（Windows 平台）：
```bash
python -c "from utils.winlog import extract_host_logs_from_windows_eventlog as f; print(f(max_events=5))"
```

离线 NDJSON：
```bash
python -c "from utils.winlog import extract_host_logs_from_winlogbeat_ndjson as f; print(f('sample_winlogbeat.ndjson', strict=False)[:3])"
```

## 11. 配置项（环境变量）

软同步可配置项（可选）：
- `TIME_SYNC_PORT`（默认 18080）
- `TIME_SYNC_BIND`（默认 0.0.0.0）
- `TIME_SYNC_SAMPLES`（默认 10）
- `TIME_SYNC_TIMEOUT_SEC`（默认 2.0）

数据库连接配置：见 `config.py`

## 12. 已知限制 / TODO

- 若 Windows Security 通道访问被拒绝，需要管理员权限或加入 Event Log Readers 组。
- 数据量较大时，全量聚合会较慢；LogonTracer 默认限制 30 天范围。
- HostLogs 只存入库时间 `create_time`，事件时间位于 `result.timestamp`。
- 可进一步扩展文件/注册表审计事件映射（需开启对象访问审计）。
