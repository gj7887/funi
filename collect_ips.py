try:
    import requests
    from bs4 import BeautifulSoup
except ImportError as e:
    print(f"缺少必要模块: {e}. 请运行 'pip install requests beautifulsoup4'")
    exit(1)

import re
import os
import time
import csv
import logging
import json
import ipaddress
from requests.exceptions import RequestException
from concurrent.futures import ThreadPoolExecutor

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("fetch_ips.log", encoding="utf-8"),
        logging.StreamHandler()
    ]
)

# 配置参数
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
REQUEST_DELAY = 2  # 请求延迟(秒)
OUTPUT_FILE = os.path.join(os.getcwd(), 'ip.csv')

def load_urls_from_file(file_path):
    """从文件加载 URL 列表"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)  # 假设文件是 JSON 格式
    except Exception as e:
        logging.error(f"加载 URL 文件失败: {e}")
        return []

# 替换硬编码的 URL 列表
URLS = [
    {"url": "https://www.wetest.vip/page/cloudflare/address_v4.html", "element": "tr"},
    {"url": "https://www.wetest.vip/page/cloudfront/address_v4.html", "element": "tr"},
]

# 正则表达式用于匹配IP地址(更精确的IPv4匹配)
IP_PATTERN = r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'

def fetch_html(url, headers, timeout=10):
    """获取网页HTML内容"""
    try:
        response = requests.get(url, headers=headers, timeout=timeout)
        response.raise_for_status()  # 检查请求是否成功
        return response.text
    except requests.exceptions.HTTPError as http_err:
        logging.error(f"HTTP 错误: {http_err} (URL: {url})")
    except requests.exceptions.ConnectionError as conn_err:
        logging.error(f"连接错误: {conn_err} (URL: {url})")
    except requests.exceptions.Timeout as timeout_err:
        logging.error(f"请求超时: {timeout_err} (URL: {url})")
    except RequestException as req_err:
        logging.error(f"请求失败: {req_err} (URL: {url})")
    return None

def extract_ips_from_text(text, pattern):
    """从文本中提取IP地址"""
    return re.findall(pattern, text)

def is_valid_ip(ip):
    """验证 IP 地址是否有效"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def save_ips_to_csv(ip_set, filename):
    """将IP地址保存到CSV文件"""
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["IP Address"])  # 写入表头
            for ip in sorted(ip_set):
                writer.writerow([ip])
        logging.info(f"成功保存 {len(ip_set)} 个唯一IP地址到 {filename}")
    except IOError as e:
        logging.error(f"写入文件 {filename} 失败: {e}")

def process_url(site):
    url = site['url']
    element = site['element']
    headers = {'User-Agent': USER_AGENT}
    unique_ips = set()

    html = fetch_html(url, headers)
    if not html:
        return unique_ips

    try:
        soup = BeautifulSoup(html, 'html.parser')
        elements = soup.find_all(element)
        for el in elements:
            text = el.get_text()
            ips = extract_ips_from_text(text, IP_PATTERN)
            unique_ips.update(ips)
    except Exception as e:
        logging.error(f"解析 {url} 时出错: {e}")
    return unique_ips

def main():
    with ThreadPoolExecutor(max_workers=5) as executor:
        results = executor.map(process_url, URLS)
    
    # 合并所有结果
    all_ips = set()
    for ips in results:
        all_ips.update(ips)
    
    # 保存结果
    if all_ips:
        save_ips_to_csv(all_ips, OUTPUT_FILE)
    else:
        logging.info("没有找到任何有效的IP地址")

if __name__ == '__main__':
    main()