import requests
import time
import logging

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

#----------------------------------------------------------------------
# 简易实现分析攻击者和C2服务器的基础设施关联信息
#----------------------------------------------------------------------

class VirusTotalEnricher:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": self.api_key
        }
        # 简单内存缓存，避免重复查询浪费配额
        self.cache = {}

    def get_domain_report(self, domain):
        """
        查询域名的详细信息：Whois, 历史解析, 关联样本
        """
        # 1. 检查缓存
        if domain in self.cache:
            logging.info(f"[Cache] 命中缓存: {domain}")
            return self.cache[domain]

        url = f"{self.base_url}/domains/{domain}"

        try:
            # 2. 发起请求
            response = requests.get(url, headers=self.headers)

            # 3. 处理频率限制 (429 Too Many Requests)
            if response.status_code == 429:
                logging.warning("API 配额超限，等待 15 秒...")
                time.sleep(15)
                return self.get_domain_report(domain)  # 重试

            if response.status_code != 200:
                logging.error(f"查询失败 {domain}: {response.status_code} - {response.text}")
                return None

            data = response.json().get('data', {}).get('attributes', {})

            # 4. 提取关键字段 (根据你的题目要求)
            parsed_info = {
                "source": "VirusTotal",
                # --- 基础信息 ---
                "domain": domain,
                "reputation_score": data.get('last_analysis_stats', {}).get('malicious', 0),
                "categories": data.get('categories', {}),

                # --- 注册信息 (Whois) ---
                "registrar": data.get('registrar'),
                "creation_date": data.get('creation_date'),  # 时间戳
                "whois_raw": data.get('whois'),  # 原始 Whois 文本

                # --- 基础设施关联 ---
                # 注意：免费版 API 可能只返回最近的解析记录
                "last_dns_records": [
                    rec.get('value')
                    for rec in data.get('last_dns_records', [])
                    if rec.get('type') == 'A'
                ],

                # --- 威胁情报标签 ---
                "tags": data.get('tags', [])
            }

            # 写入缓存
            self.cache[domain] = parsed_info
            logging.info(f"[API] 成功获取情报: {domain}")
            return parsed_info

        except Exception as e:
            logging.error(f"API 请求异常: {e}")
            return None

    def get_ip_report(self, ip):
        """
        查询 IP 的地理位置、归属 ASN 等
        """
        if ip in self.cache: return self.cache[ip]

        url = f"{self.base_url}/ip_addresses/{ip}"
        try:
            response = requests.get(url, headers=self.headers)
            if response.status_code == 200:
                data = response.json().get('data', {}).get('attributes', {})
                result = {
                    "ip": ip,
                    "country": data.get("country"),
                    "asn": data.get("asn"),
                    "as_owner": data.get("as_owner"),
                    "reputation": data.get("last_analysis_stats", {}).get("malicious", 0)
                }
                self.cache[ip] = result
                return result
        except Exception:
            pass
        return None