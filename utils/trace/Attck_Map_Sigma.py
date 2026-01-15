import yaml
import os
import uuid
import logging
from datetime import datetime
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class SigmaMapper:
    def __init__(self, rules_dir='sigma_rules/'):
        """
        :param rules_dir: 存放 .yml Sigma 规则的目录
        """
        self.rules_dir = rules_dir
        self.rules = self._load_sigma_rules()

        # 建立 Tactic 到 Stage 的映射 (解决你的问题2)
        self.tactic_stage_map = {
            "reconnaissance": 1, "resource_development": 1,
            "initial_access": 2,
            "execution": 3, "persistence": 3,
            "privilege_escalation": 4, "defense_evasion": 4,
            "credential_access": 5,
            "discovery": 6,
            "lateral_movement": 7,
            "collection": 8,
            "command_and_control": 9,
            "exfiltration": 10,
            "impact": 11
        }

    def _load_sigma_rules(self):
        """
        加载指定目录下的所有 Sigma 规则
        """
        loaded_rules = []
        if not os.path.exists(self.rules_dir):
            logging.warning(f"Sigma 规则目录不存在: {self.rules_dir}")
            return []

        # 遍历读取 YAML
        for root, _, files in os.walk(self.rules_dir):
            for file in files:
                if file.endswith(".yml") or file.endswith(".yaml"):
                    try:
                        with open(os.path.join(root, file), 'r', encoding='utf-8') as f:
                            rule_content = yaml.safe_load(f)
                            # 简单的过滤：只处理 process_creation 或 file_event 等
                            if self._is_supported_category(rule_content):
                                loaded_rules.append(rule_content)
                    except Exception as e:
                        logging.error(f"加载规则 {file} 失败: {e}")

        logging.info(f"成功加载 {len(loaded_rules)} 条 Sigma 规则")
        return loaded_rules

    def _is_supported_category(self, rule):
        # 根据 logsource 过滤，例如只支持 windows sysmon 或 process_creation
        category = rule.get('logsource', {}).get('category', '').lower()
        product = rule.get('logsource', {}).get('product', '').lower()
        return category in ['process_creation', 'network_connection', 'file_event'] or product == 'windows'

    def _flatten_event(self, event_data):
        """
        [关键步骤] 将你的嵌套 Event 结构 展平 为 Sigma 喜欢的扁平结构 (Key-Value)
        并进行字段重命名以匹配 Sigma 标准
        """
        flat = {}
        entities = event_data.get('entities', {})

        # 1. 基础字段
        flat['EventID'] = event_data.get('raw_id')

        # 2. 映射 Process 字段
        if event_data.get('event_type') == 'process_create':
            flat['Image'] = entities.get('process_name')
            flat['CommandLine'] = entities.get('command_line')
            flat['ParentImage'] = entities.get('parent_process')
            flat['ParentCommandLine'] = entities.get('parent_command_line', '')  # 假设你有
            flat['User'] = entities.get('user')

        # 3. 映射 Network 字段
        elif event_data.get('event_type') == 'network_connection':
            flat['DestinationIp'] = entities.get('dst_ip')
            flat['DestinationPort'] = entities.get('dst_port')
            flat['Image'] = entities.get('process_name')

        # 4. 保留原始值防止匹配不到
        for k, v in entities.items():
            flat[k] = v

        return flat

    def _match_condition(self, detection, flat_event):
        """
        [简化版匹配引擎]
        Sigma 的 detection 部分包含 selection 和 condition。
        这是一个非常简化的 Python 字典匹配逻辑，用于替代复杂的 pySigma Backend。
        真实生产环境建议使用专门的 Sigma Python Evaluator。
        """
        # 解析 condition 字符串 (如 "selection1 and not selection2") 比较复杂
        # 这里演示最常见的 "Keywords Matching" 逻辑

        matched_selections = []

        for key, value in detection.items():
            if key == 'condition': continue

            # value 是一个匹配条件，例如 {'Image|endswith': 'cmd.exe'}
            is_match = True

            # 处理列表形式 (OR 关系)
            if isinstance(value, list):
                # 列表中只要有一个匹配即可
                sub_match = False
                for item in value:
                    if self._check_single_selection(item, flat_event):
                        sub_match = True
                        break
                if not sub_match:
                    is_match = False
            else:
                # 字典形式 (AND 关系)
                if not self._check_single_selection(value, flat_event):
                    is_match = False

            if is_match:
                matched_selections.append(key)

        # 简单处理 condition: 只要有任何 selection 匹配成功，且 condition 包含该 selection
        condition = detection.get('condition', '')
        # 如果 condition 是 'all of them' 或 简单的 'selection'
        if matched_selections:
            # TODO: 实现完整的 boolean logic parser
            # 这里做个大胆的假设：如果匹配到了任意关键词，先算作 Trigger，后续再人工降噪
            # 这是“宁可误报不可漏报”的策略
            return True

        return False

    def _check_single_selection(self, criteria, event):
        """检查单个字典条件是否在 event 中满足"""
        if not isinstance(criteria, dict): return False

        for field, pattern in criteria.items():
            field_name = field.split('|')[0]  # 处理 Image|endswith
            modifier = field.split('|')[1] if '|' in field else 'equals'

            event_val = event.get(field_name)
            if not event_val: return False

            # 转换为字符串比较
            event_val = str(event_val).lower()
            pattern = str(pattern).lower()

            if modifier == 'endswith':
                if not event_val.endswith(pattern): return False
            elif modifier == 'startswith':
                if not event_val.startswith(pattern): return False
            elif modifier == 'contains':
                if pattern not in event_val: return False
            else:  # equals
                if event_val != pattern: return False

        return True

    def analyze_event(self, event_data):
        """
        替代原本的 analyze_event
        """
        matches = []
        flat_event = self._flatten_event(event_data)

        for rule in self.rules:
            detection = rule.get('detection', {})
            if self._match_condition(detection, flat_event):
                # === 提取 ATT&CK 信息 (解决问题2) ===
                tags = rule.get('tags', [])
                attck_id = next((t.split('.')[1].upper() for t in tags if t.startswith('attack.t')), None)
                tactic_slug = next((t.split('.')[1] for t in tags if t.startswith('attack.') and not t[7].isdigit()),
                                   None)

                # 自动计算 Stage
                stage_order = self.tactic_stage_map.get(tactic_slug, 0)  # 默认为0

                matches.append({
                    "attack_id": str(uuid.uuid4()),
                    "rule_id": rule.get('id'),
                    "tactic": {
                        "id": "Unknown",  # 可以维护一个 Tactic ID 映射表
                        "name": tactic_slug or "Unknown"
                    },
                    "technique": {
                        "id": attck_id or "Unknown",
                        "name": rule.get('title')  # Sigma title 通常就是攻击行为描述
                    },
                    "confidence": rule.get('level', 'medium').capitalize(),
                    "timestamp_start": event_data.get('timestamp'),
                    "timestamp_end": event_data.get('timestamp'),
                    "victim_ip": event_data.get('host_ip'),
                    "stage_order": stage_order,  # 动态获取
                    "description": rule.get('description'),
                    # 将触发规则的实体ID传回去，用于构图
                    "related_events": [self._generate_event_id(event_data)]
                })

        return matches

    def _generate_event_id(self, event):
        """
        生成与图数据库实体节点一致的 ID，用于建立 TRIGGERED 关系。
        规则参考《数据库设计字典》第一层：实体层。
        """
        data_source = event.get('data_source')
        entities = event.get('entities', {})
        host_ip = event.get('host_ip')

        # 1. 进程相关行为 (Process Node ID: HostIP_PID_CreateTime)
        # 注意：如果是 process_create，timestamp 就是 CreateTime
        # 如果是其他行为（如 file_create），理想情况是知道发起进程的启动时间，
        # 但如果不知道，这里只能尽可能返回能标识该进程的ID。
        # 简化策略：如果是 process_create，使用当前时间戳作为后缀；
        # 如果是子行为，通常日志里不带父进程启动时间，可能需要基于 PID 模糊匹配（此处暂略，假设已有逻辑或仅返回 Host_PID）
        if data_source == 'host_behavior' or 'pid' in entities:
            pid = entities.get('pid')
            # 严格对应接口文档 Process 节点 ID
            # 注意：实际生产中需要缓存 PID->StartTime 的映射，这里做简化处理
            timestamp_suffix = event.get('timestamp') if event.get('event_type') == 'process_create' else 'unknown'
            if host_ip and pid:
                return f"{host_ip}_{pid}_{timestamp_suffix}"

        # 2. 网络流量相关 (Domain Node 或 IP Node)
        if data_source == 'network_traffic':
            # 如果是 DNS 隧道，关联到 Domain 节点
            if entities.get('domain'):
                return entities.get('domain')  # ID: DomainName

            # 否则关联到源 IP (作为攻击发起点或受害点)
            if event.get('src_ip'):
                return event.get('src_ip')  # ID: IP_Address

        # 3. 主机日志相关 (User Node 或 IP Node)
        if data_source == 'host_log':
            # 登录相关，关联到 User 节点 (ID: HostIP_Username)
            if 'user' in entities and host_ip:
                return f"{host_ip}_{entities['user']}"

        # 4. 注册表相关 (Registry Node)
        # 接口文档定义 ID 为 Registry_Key_Path
        if event.get('event_type') == 'registry_set_value':
            if entities.get('registry_key'):
                return entities.get('registry_key')

        # 5. 兜底：防止返回 None 导致报错
        return f"Unlinked_Event_{event.get('timestamp')}"

