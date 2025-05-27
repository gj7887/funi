import requests
from bs4 import BeautifulSoup
import re
import os
import csv
import logging
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
CONFIG = {
    'USER_AGENT': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'REQUEST_TIMEOUT': 10,
    'OUTPUT_FILE': 'ip.csv',
    'URLS': [
        {"url": "https://www.wetest.vip/page/cloudflare/address_v4.html", "element": "tr"},
        {"url": "https://www.wetest.vip/page/cloudfront/address_v4.html", "element": "tr"},
    ],
    'IP_PATTERN': r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
}

def fetch_html(url, headers):
    """获取网页HTML内容"""
    try:
        response = requests.get(url, headers=headers, timeout=CONFIG['REQUEST_TIMEOUT'])
        response.raise_for_status()
        return response.text
    except RequestException as e:
        logging.error(f"请求失败: {e} (URL: {url})")
        return None

def extract_ips(text):
    """从文本中提取IP地址"""
    return re.findall(CONFIG['IP_PATTERN'], text)

def validate_ip(ip):
    """验证IP地址有效性"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def save_results(ip_set, filename):
    """保存结果到CSV文件"""
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['IP Address'])
            writer.writerows([[ip] for ip in sorted(ip_set)])
        logging.info(f"成功保存 {len(ip_set)} 个IP地址到 {filename}")
    except IOError as e:
        logging.error(f"文件保存失败: {e}")

def process_site(site):
    """处理单个网站"""
    headers = {'User-Agent': CONFIG['USER_AGENT']}
    html = fetch_html(site['url'], headers)
    if not html:
        return set()
    
    try:
        soup = BeautifulSoup(html, 'html.parser')
        elements = soup.find_all(site['element'])
        if not elements:
            logging.warning(f"未在 {site['url']} 找到任何匹配的元素")
            return set()
        logging.info(f"从 {site['url']} 找到 {len(elements)} 个元素")
        ips = set()
        for el in elements:
            ips.update(ip for ip in extract_ips(el.get_text()) if validate_ip(ip))
        logging.info(f"从 {site['url']} 提取到 {len(ips)} 个IP地址")
        return ips
    except Exception as e:
        logging.error(f"解析错误: {e} (URL: {site['url']})")
        return set()

def main():
    """主函数"""
    all_ips = set()
    
    with ThreadPoolExecutor(max_workers=5) as executor:
        results = executor.map(process_site, CONFIG['URLS'])
        for ip_set in results:
            all_ips.update(ip_set)
    
    if all_ips:
        save_results(all_ips, CONFIG['OUTPUT_FILE'])
    else:
        logging.warning("未获取到任何有效IP地址")

if __name__ == '__main__':
    main()
