import os
import json
from openai import OpenAI
import dashscope
# 配置你的 API Key (建议放入环境变量或 config.py)
# 这里以兼容 OpenAI 格式的 API 为例（如 DeepSeek, 通义千问, 智谱 AI 或 OpenAI 自身）
API_KEY = os.getenv("LLM_API_KEY", "sk-2a3e87220c71453bbea250014bb401c7")
BASE_URL = os.getenv("LLM_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1")

client = OpenAI(api_key=API_KEY, base_url=BASE_URL)

class LLMReporter:
    def generate_narrative_report(self, attack_data):
        """
        根据溯源 JSON 数据生成人类可读的 Markdown 报告
        """
        # 1. 精简数据，防止 Token 超出或干扰 AI
        summary_data = {
            "victim": attack_data.get("victim_ip"),
            "trigger": attack_data.get("trigger_technique"),
            "attribution": attack_data.get("attacker_profile", {}).get("suspected_apt"),
            "timeline_summary": [
                f"{t.get('time')} - {t.get('summary')}"
                for t in attack_data.get("timeline", [])[:15] # 限制长度
            ],
            "impact": {
                "exfiltration": attack_data.get("paths", {}).get("exfiltration"),
                "lateral": attack_data.get("paths", {}).get("lateral_source")
            }
        }

        data_str = json.dumps(summary_data, ensure_ascii=False, indent=2)

        # 2. 构建 Prompt
        system_prompt = """你是一名高级网络安全溯源分析师。请根据提供的 JSON 攻击数据，生成一份专业的Markdown格式溯源报告。
报告语气应客观、专业、简练。
报告结构如下：
1. **事件摘要**：一句话描述谁攻击了谁，使用了什么关键技术，归因结果是什么。
2. **攻击链复盘**：按时间顺序描述攻击者的关键动作（从入侵到横向到外传）。
3. **归因分析**：基于 TTP 和 IOC，分析攻击者特征。如果是 Known APT，说明组织背景；如果是 Unknown，描述其行为画像。
4. **处置建议**：针对性给出 3 条阻断或加固建议。
"""

        user_prompt = f"请基于以下攻击数据生成报告：\n\n{data_str}"

        # 3. 调用模型
        try:
            response = client.chat.completions.create(
                model="qwen-flash",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.3 # 低温度保证事实性
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"报告生成失败: {str(e)}"