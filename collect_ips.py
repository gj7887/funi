import requests
from bs4 import BeautifulSoup
import re
import os
import csv
import logging
import ipaddress
import time
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
    'IPV4_OUTPUT': 'ipv4.csv',
    'IPV6_OUTPUT': 'ipv6.csv',
    'TEST_RESULT_FILE': 'ip_test_result.csv',
    'MAX_IPV4': 15,
    'MAX_IPV6': 15,
    'PING_TIMEOUT': 3,
    'SPEED_TEST_SIZE': 1024,  # 1KB测试数据
    'URLS': [
        {"url": "https://www.wetest.vip/page/cloudflare/address_v4.html", "element": "tr"},
        {"url": "https://www.wetest.vip/page/cloudfront/address_v4.html", "element": "tr"},
        {"url": "https://www.wetest.vip/page/cloudflare/address_v6.html", "element": "tr"},
        {"url": "https://www.wetest.vip/page/cloudfront/address_v6.html", "element": "tr"},
    ],
    'IP_PATTERN': r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
    'IPv6_PATTERN': r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
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
    """从文本中提取IP地址,分别返回IPv4和IPv6"""
    ipv4_ips = re.findall(CONFIG['IP_PATTERN'], text)
    ipv6_ips = re.findall(CONFIG['IPv6_PATTERN'], text)
    return ipv4_ips, ipv6_ips

def validate_ip(ip):
    """验证IP地址有效性"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def save_results(ip_list, filename):
    """保存结果到CSV文件"""
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerows([[ip] for ip in ip_list])
        logging.info(f"成功保存 {len(ip_list)} 个IP地址到 {filename}")
    except IOError as e:
        logging.error(f"文件保存失败: {e}")

def test_ip_connection(ip, port=80):
    """测试IP连接延迟"""
    import socket
    try:
        sock = socket.socket(socket.AF_INET if ':' not in ip else socket.AF_INET6, socket.SOCK_STREAM)
        sock.settimeout(CONFIG['PING_TIMEOUT'])
        start_time = time.time()
        sock.connect((ip, port))
        end_time = time.time()
        sock.close()
        latency = round((end_time - start_time) * 1000, 2)  # 转换为毫秒
        return latency
    except Exception as e:
        logging.warning(f"IP {ip} 连接测试失败: {e}")
        return None

def test_ip_speed(ip, port=80):
    """测试IP下载速度 (KB/s)"""
    import socket
    try:
        sock = socket.socket(socket.AF_INET if ':' not in ip else socket.AF_INET6, socket.SOCK_STREAM)
        sock.settimeout(CONFIG['PING_TIMEOUT'])
        start_time = time.time()
        sock.connect((ip, port))
        # 发送测试数据
        test_data = b'A' * CONFIG['SPEED_TEST_SIZE']
        sock.sendall(test_data)
        end_time = time.time()
        sock.close()
        duration = end_time - start_time
        if duration > 0:
            speed = round((CONFIG['SPEED_TEST_SIZE'] / 1024) / duration, 2)  # KB/s
            return speed
        return None
    except Exception as e:
        logging.warning(f"IP {ip} 速度测试失败: {e}")
        return None

def save_test_results(results, filename):
    """保存测试结果到CSV文件"""
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['IP地址', '延迟(ms)', '下载速度(KB/s)', '状态'])
            for result in results:
                status = '可用' if result['latency'] is not None else '不可用'
                writer.writerow([result['ip'], result['latency'], result['speed'], status])
        logging.info(f"成功保存 {len(results)} 个IP测试结果到 {filename}")
    except IOError as e:
        logging.error(f"测试结果保存失败: {e}")

def process_site(site):
    """处理单个网站,返回IPv4和IPv6集合"""
    headers = {'User-Agent': CONFIG['USER_AGENT']}
    html = fetch_html(site['url'], headers)
    if not html:
        return set(), set()
    
    try:
        soup = BeautifulSoup(html, 'html.parser')
        elements = soup.find_all(site['element'])
        if not elements:
            logging.warning(f"未在 {site['url']} 找到任何匹配的元素")
            return set(), set()
        logging.info(f"从 {site['url']} 找到 {len(elements)} 个元素")
        ipv4_ips = set()
        ipv6_ips = set()
        for el in elements:
            ipv4_list, ipv6_list = extract_ips(el.get_text())
            ipv4_ips.update(ip for ip in ipv4_list if validate_ip(ip))
            ipv6_ips.update(ip for ip in ipv6_list if validate_ip(ip))
        logging.info(f"从 {site['url']} 提取到 {len(ipv4_ips)} 个IPv4, {len(ipv6_ips)} 个IPv6")
        return ipv4_ips, ipv6_ips
    except Exception as e:
        logging.error(f"解析错误: {e} (URL: {site['url']})")
        return set(), set()

def main():
    """主函数"""
    all_ipv4 = set()
    all_ipv6 = set()
    
    with ThreadPoolExecutor(max_workers=5) as executor:
        results = executor.map(process_site, CONFIG['URLS'])
        for ipv4_set, ipv6_set in results:
            all_ipv4.update(ipv4_set)
            all_ipv6.update(ipv6_set)
    
    # 转换为列表并排序
    ipv4_list = sorted(all_ipv4)
    ipv6_list = sorted(all_ipv6)
    
    # 限制数量
    ipv4_list = ipv4_list[:CONFIG['MAX_IPV4']]
    ipv6_list = ipv6_list[:CONFIG['MAX_IPV6']]
    
    if ipv4_list:
        save_results(ipv4_list, CONFIG['IPV4_OUTPUT'])
    else:
        logging.warning("未获取到任何IPv4地址")
    
    if ipv6_list:
        save_results(ipv6_list, CONFIG['IPV6_OUTPUT'])
    else:
        logging.warning("未获取到任何IPv6地址")
    
    # 同时保存到总文件
    all_ips = ipv4_list + ipv6_list
    if all_ips:
        save_results(all_ips, CONFIG['OUTPUT_FILE'])
    
    # 进行延迟和网速测试
    if all_ips:
        logging.info("开始进行延迟和网速测试...")
        test_results = []
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            # 测试所有IP的延迟
            latency_results = list(executor.map(lambda ip: (ip, test_ip_connection(ip)), all_ips))
            
            # 测试所有IP的速度
            speed_results = list(executor.map(lambda ip: (ip, test_ip_speed(ip)), all_ips))
        
        # 合并结果
        latency_dict = {ip: latency for ip, latency in latency_results}
        speed_dict = {ip: speed for ip, speed in speed_results}
        
        for ip in all_ips:
            test_results.append({
                'ip': ip,
                'latency': latency_dict.get(ip),
                'speed': speed_dict.get(ip)
            })
        
        # 按延迟排序
        test_results.sort(key=lambda x: (x['latency'] is None, x['latency']))
        
        # 保存测试结果
        save_test_results(test_results, CONFIG['TEST_RESULT_FILE'])
        
        # 输出统计信息
        available_ips = [r for r in test_results if r['latency'] is not None]
        if available_ips:
            avg_latency = sum(r['latency'] for r in available_ips) / len(available_ips)
            avg_speed = sum(r['speed'] for r in available_ips if r['speed']) / len([r for r in available_ips if r['speed']]) if any(r['speed'] for r in available_ips) else 0
            logging.info(f"可用IP数量: {len(available_ips)}/{len(all_ips)}")
            logging.info(f"平均延迟: {avg_latency:.2f}ms")
            logging.info(f"平均速度: {avg_speed:.2f}KB/s")
            
            # 输出最优的5个IP
            logging.info("最优的5个IP:")
            for i, result in enumerate(available_ips[:5], 1):
                speed_info = f"{result['speed']}KB/s" if result['speed'] else "N/A"
                logging.info(f"  {i}. {result['ip']} - 延迟: {result['latency']}ms, 速度: {speed_info}")

if __name__ == '__main__':
    main()
