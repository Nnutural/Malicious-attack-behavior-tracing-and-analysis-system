import yaml
import uuid
import os
import logging
from collections import defaultdict, deque
from datetime import datetime, timedelta
# 配置简单的日志，方便调试
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class EventAggregator:
    def __init__(self, default_window_seconds=60):
        """
        初始化聚合器
        :param default_window_seconds: 默认的时间窗口大小（秒）
        """
        self.window = default_window_seconds
        # 缓存结构: {(host_ip, event_type): deque([time1, time2, ...])}
        self.buffer = defaultdict(deque)

    def check_threshold(self, event, threshold_count):
        """
        检查是否在时间窗口内达到了次数阈值
        :param event: 当前处理的事件字典
        :param threshold_count: 触发告警所需的最小次数
        :return: Boolean (True 表示达到阈值，应该报警)
        """
        # 1. 构造唯一键 (区分不同主机的同类事件)
        host_ip = event.get('host_ip') or event.get('src_ip')
        event_type = event.get('event_type')

        if not host_ip or not event_type:
            return False

        key = (host_ip, event_type)

        # 2. 解析时间 (假设输入是 ISO8601 字符串)
        try:
            # 注意：需根据实际数据格式调整 strptime
            # 这里简化处理，假设数据带 'Z'
            ts_str = event.get('timestamp').replace('Z', '')
            current_time = datetime.fromisoformat(ts_str)
        except Exception:
            # 如果时间解析失败，使用当前系统时间兜底
            current_time = datetime.utcnow()

        # 3. 滑动窗口逻辑
        # 3.1 记入当前事件
        self.buffer[key].append(current_time)

        # 3.2 移除过期事件 (即：当前时间 - 最早记录时间 > 窗口大小)
        while self.buffer[key]:
            earliest_time = self.buffer[key][0]
            if (current_time - earliest_time).total_seconds() > self.window:
                self.buffer[key].popleft()
            else:
                break  # 队列是有序的，如果头部没过期，后面的肯定也没过期

        # 4. 判断阈值
        # 只有当数量 刚好等于 阈值时触发（避免第6次、第7次重复报警）
        # 或者根据需求设为 >= 并定期清理
        if len(self.buffer[key]) == threshold_count:
            return True

        return False

class ATTACKMapper:
    def __init__(self, rules_file='attack_rules.yaml'):
        """
        初始化映射器
        :param rules_file: YAML规则文件的路径
        """
        self.rules = self._load_rules(rules_file)
        # [新增] 初始化聚合器，默认窗口60秒
        self.aggregator = EventAggregator(default_window_seconds=60)

    def _load_rules(self, file_path):
        """
        从YAML文件加载规则，包含错误处理
        """
        # 1. 检查文件是否存在
        if not os.path.exists(file_path):
            logging.error(f"规则文件未找到: {file_path}")
            return []

        # 2. 读取并解析YAML
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                # safe_load 比 load 更安全，防止代码注入
                rules = yaml.safe_load(f)

                if not rules:
                    logging.warning("规则文件为空")
                    return []

                logging.info(f"成功加载 {len(rules)} 条ATT&CK映射规则")
                return rules

        except yaml.YAMLError as e:
            logging.error(f"YAML格式解析错误: {e}")
            return []
        except Exception as e:
            logging.error(f"读取规则文件时发生未知错误: {e}")
            return []

    def analyze_event(self, event_data):
        """
        核心函数：接收单条归一化后的数据，返回ATT&CK映射结果
        """
        if not self.rules:
            logging.warning("规则库为空，无法执行分析")
            return []

        matched_attacks = []

        # 1. 提取基础信息
        data_source = event_data.get("data_source")
        event_type = event_data.get("event_type")
        # 合并特征方便查找
        features = {}
        if "behavior_features" in event_data:
            features.update(event_data["behavior_features"])
        if "traffic_features" in event_data:
            features.update(event_data["traffic_features"])

        # 2. 遍历规则库进行匹配
        for rule in self.rules:
            # 2.1 检查数据源是否匹配
            if rule.get('data_source') != data_source:
                continue

            # 2.2 检查事件类型是否匹配
            trigger = rule.get('trigger', {})
            if trigger.get('event_type') != event_type:
                continue

            # ================= [新增/修改逻辑] =================
            # 检查是否需要聚合 (例如暴力破解规则)
            # 假设我们在 yaml 规则中增加了一个字段 'threshold'
            # 如果规则没写 threshold，默认为 1 (即单条触发)
            rule_threshold = rule.get('trigger', {}).get('threshold', 1)

            is_triggered = False

            if rule_threshold > 1:
                    # 调用聚合器检查
                if self.aggregator.check_threshold(event_data, rule_threshold):
                    is_triggered = True
            else:
                # 2.3 检查特征条件 (Features)
                feature_match = True

                # 检查 behavior_features
                if 'behavior_features' in trigger:
                    for key, val in trigger['behavior_features'].items():
                        # 只有当特征存在且值相等时才算匹配
                        if features.get(key) != val:
                            feature_match = False
                            break

                # 检查 traffic_features
                if feature_match and 'traffic_features' in trigger:
                    for key, val in trigger['traffic_features'].items():
                        if features.get(key) != val:
                            feature_match = False
                            break

                if feature_match:
                    is_triggered = True

            if is_triggered:
                # ... (构造输出 attack_result 的代码不变) ...
                # 只是这里要注意，timestamp_start 可能是聚合窗口的开始时间
                # 但简单起见，仍使用当前事件时间
                pass
                # 把原代码里的 构造输出 部分放在这里

                # (为了完整性，这里补全原代码的构造逻辑)
                attack_mapping = rule.get('attack_mapping', {})
                attack_result = {
                    "attack_id": str(uuid.uuid4()),
                    "tactic": {
                        "id": attack_mapping.get('tactic_id'),
                        "name": attack_mapping.get('tactic_name')
                    },
                    "technique": {
                        "id": attack_mapping.get('technique_id'),
                        "name": attack_mapping.get('technique_name')
                    },
                    "related_events": [self._generate_event_id(event_data)],
                    "confidence": "High",
                    "timestamp_start": event_data.get("timestamp"),
                    "timestamp_end": event_data.get("timestamp"),
                    "victim_ip": event_data.get("host_ip") or event_data.get("src_ip"),
                    "attacker_ip": self._extract_attacker_ip(event_data),
                    "stage_order": self._determine_stage(attack_mapping.get('tactic_name'))
                }
                matched_attacks.append(attack_result)
        return matched_attacks

    def _extract_attacker_ip(self, event):
        if event.get('data_source') == 'network_traffic':
            return event.get('dst_ip')
        if 'entities' in event:
            return event['entities'].get('src_ip')
        return None

    def _generate_event_id(self, event):
        if event.get('data_source') in ['host_behavior', 'host_log']:
            host_ip = event.get('host_ip')
            entities = event.get('entities', {})
            pid = entities.get('pid')

            if host_ip and pid:
                # 逻辑必须与 Graph_construct.py 保持完全一致
                if event.get('event_type') == 'process_create':
                    time_suffix = event.get('timestamp')
                else:
                    time_suffix = 'unknown'
                return f"{host_ip}_{pid}_{time_suffix}"

            # 2. 如果是网络流量，优先返回 Domain ID 或 IP ID
        if event.get('data_source') == 'network_traffic':
            entities = event.get('entities', {})
            if entities.get('domain'):
                return entities.get('domain')
            if event.get('src_ip'):
                return event.get('src_ip')

            # 3. 兜底：返回旧格式 (虽然匹配不到实体，但至少有记录)
        return f"{event.get('data_source')}_{event.get('timestamp')}_{event.get('event_type')}"

    def _determine_stage(self, tactic_name):
        stages = {
            "Reconnaissance": 1, "Resource Development": 1,
            "Initial Access": 2, "Execution": 3, "Persistence": 3,
            "Privilege Escalation": 4, "Defense Evasion": 4,
            "Credential Access": 5, "Discovery": 6, "Lateral Movement": 7,
            "Collection": 8, "Command and Control": 9, "Exfiltration": 10, "Impact": 11
        }
        return stages.get(tactic_name, 0)


# ==========================================
# 4. 测试运行 (Main)
# ==========================================
if __name__ == "__main__":
    # 实例化 Mapper，它会自动读取当前目录下的 attack_rules.yaml
    mapper = ATTACKMapper("attack_rules.yaml")

    # 模拟输入数据：隐蔽信道
    traffic_event =         {
            "data_source": "host_behavior",
            "timestamp": "2023-10-27T10:06:00Z",
            "host_ip": "192.168.1.100",
            "event_type": "registry_set_value",
            "entities": {
                "process_name": "malware.exe",
                "pid": 5555,
                "registry_key": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Evil",
                "registry_value_name": "Evil",
                "registry_value_data": "C:\\Temp\\malware.exe"
            },
            "behavior_features": {}
        }

    # 执行分析
    results = mapper.analyze_event(traffic_event)

    # 打印结果
    import json

    print(json.dumps(results, indent=4, ensure_ascii=False))