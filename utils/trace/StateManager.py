import json
import os
import logging


class StateManager:
    def __init__(self, state_file='system_state.json'):
        self.state_file = state_file
        self.state = self._load_state()

    def _load_state(self):
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r') as f:
                    return json.load(f)
            except Exception:
                logging.warning("状态文件损坏，重置为初始状态")

        # 初始状态
        return {
            "checkpoints": {
                "HostLogs": 0,
                "HostBehaviors": 0,
                "NetworkTraffic": 0
            },
            "pid_cache": {}  # 保存 (IP, PID) -> Timestamp 的映射
        }

    def save_state(self):
        """保存当前进度到磁盘"""
        with open(self.state_file, 'w') as f:
            json.dump(self.state, f, indent=4)
        logging.info("系统状态已保存 (Checkpoints & Cache)")

    def get_checkpoint(self, table_name):
        return self.state["checkpoints"].get(table_name, 0)

    def update_checkpoint(self, table_name, new_id):
        self.state["checkpoints"][table_name] = new_id

    def get_pid_cache(self):
        # JSON 的 key 只能是字符串，读取时需要把 "ip,pid" 字符串转换回 tuple key 供程序使用
        # 这里简化处理：我们在 Graph_construct 里直接用 StateManager
        return self.state["pid_cache"]

    def update_pid_cache(self, new_cache):
        self.state["pid_cache"] = new_cache