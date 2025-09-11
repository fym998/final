import os
import json
import argparse
import ipaddress
import requests
import whois
import tldextract
import re
from tqdm import tqdm
import threading
import socket

# 设置全局变量
WHOIS_API_KEY = None

# 已知的CDN和云服务提供商域名模式
CDN_PATTERNS = {
    'aliyun': r'.*\.aliyuncs\.com$',
    'alicloud': r'.*\.alicdn\.com$',
    'cloudflare': r'.*\.cloudflare\.net$',
    'amazon': r'.*\.cloudfront\.net$',
    'amazon': r'.*\.amazonaws\.com$',
    'azure': r'.*\.azure\.com$',
    'google': r'.*\.googleapis\.com$',
    'google': r'.*\.gstatic\.com$',
    'tencent': r'.*\.tencent-cloud\.net$',
    'huawei': r'.*\.dbankcloud\.cn$',
    'huawei': r'.*\.dbankedge\.cn$',
    'huawei': r'.*\.hicloud\.com$',
    'cdn': r'.*\.cdnhwc\d\.com$',
    'cdn': r'.*\.cdngslb\.com$',
    'kunlun': r'.*\.kunlun\.com$',
    'wangsu': r'.*\.lxdns\.com$',
    'qiniu': r'.*\.qiniucdn\.com$',
    'volcengine': r'.*\.volcengine\.com$',
    'volcengine': r'.*\.volces\.com$',
}

# 内部域名和需要过滤的域名模式
INTERNAL_DOMAIN_PATTERNS = [
    r'.*\.mshome\.net$',  # Windows Internet Connection Sharing
    r'.*\.local$',  # mDNS (Multicast DNS)
    r'.*\.home$',  # 家庭网络
    r'.*\.lan$',  # 局域网
    r'.*\.localdomain$',  # 本地域
    r'.*\.arpa$',  # 反向DNS查询
    r'^https$',  # 协议名称
    r'^http$',  # 协议名称,
]

# 需要过滤的域名关键词
DOMAIN_KEYWORDS_TO_FILTER = [
    'in-addr.arpa',
    'ip6.arpa',
    'localhost',
    'broadcasthost',
]

# 车企关键词列表 - 扩展版
AUTO_COMPANY_KEYWORDS = [
    # 国际车企
    'toyota', 'honda', 'nissan', 'mazda', 'subaru', 'mitsubishi',  # 日本
    'ford', 'chevrolet', 'gm', 'general motors', 'chrysler', 'dodge', 'jeep', 'tesla',  # 美国
    'volkswagen', 'audi', 'bmw', 'mercedes', 'benz', 'porsche', 'opel',  # 德国
    'volvo', 'saab',  # 瑞典
    'fiat', 'ferrari', 'lamborghini', 'maserati',  # 意大利
    'renault', 'peugeot', 'citroen',  # 法国
    'hyundai', 'kia',  # 韩国
    'geely', 'byd', 'chery', 'great wall', 'haval', 'changan', 'saic', 'dongfeng',  # 中国
    'tata', 'mahindra',  # 印度
    
    # 汽车相关术语
    'auto', 'automotive', 'car', 'vehicle', 'motor', 'mobility',
    'dealership', 'dealer', 'autohaus', 'autocenter',
    'parts', 'service', 'repair', 'maintenance',
    'leasing', 'rental', 'finance', 'insurance',
    
    # 供应商
    'bosch', 'continental', 'denso', 'delphi', 'magna', 'valeo', 'zf', 'aic',
    'aptiv', 'faurecia', 'lear', 'adient', 'yazaki', 'sumitomo', 'jtekt',
    'bridgestone', 'michelin', 'goodyear', 'pirelli',
    
    # 汽车技术
    'adas', 'autonomous', 'connected', 'electric', 'ev', 'hybrid',
    'telematics', 'infotainment', 'navigation', 'gps',
    'obd', 'diagnostics', 'ecu', 'canbus',
    
    # 中国车企特定关键词
    'baidu', 'duer', 'dueros', 'mapauto', 'autonavi', 'amap',
    'autochips', 'horizon', 'neusoft', 'desay', 'visteon',
    'yutong', 'zhongtong', 'kinglong', 'foton', 'jac',
    'chery', 'lifan', 'gac', 'brilliance', 'jac',
    'wey', 'lynk', 'zeekr', 'nio', 'xpeng', 'li', 'lixiang',
    'haima', 'soueast', 'besturn', 'hongqi', 'jetta',
    'roewe', 'mg', 'maxus', 'skyworth', 'seres',
    
    # 车联网相关
    'tsp', 'telematics', 'v2x', 'v2v', 'v2i', 'v2g',
    'connected car', 'smart car', 'intelligent vehicle',
    'carplay', 'android auto', 'carlife',
    'tbox', 'obd', 'can bus', 'ecu'
]

# 线程安全的缓存
class ThreadSafeCache:
    def __init__(self, maxsize=10000):
        self.cache = {}
        self.maxsize = maxsize
        self.lock = threading.Lock()

    def get(self, key):
        with self.lock:
            return self.cache.get(key)

    def set(self, key, value):
        with self.lock:
            if len(self.cache) >= self.maxsize:
                # 移除最旧的一项
                self.cache.pop(next(iter(self.cache)))
            self.cache[key] = value

# 全局缓存
geoip_cache = ThreadSafeCache(maxsize=50000)
whois_cache = ThreadSafeCache(maxsize=50000)

def is_private_ip(ip):
    """检查是否为私有IP地址"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return True

def is_internal_domain(domain):
    """检查是否为内部域名或需要过滤的域名"""
    if not domain or len(domain) < 3:
        return True

    # 检查域名关键词
    for keyword in DOMAIN_KEYWORDS_TO_FILTER:
        if keyword in domain:
            return True

    # 检查域名模式
    for pattern in INTERNAL_DOMAIN_PATTERNS:
        if re.match(pattern, domain, re.IGNORECASE):
            return True

    # 检查短域名（可能是无效域名）
    if len(domain.split('.')) < 2:
        return True

    # 检查类似 y.iO、MH.hK 这样的短域名
    domain_parts = domain.split('.')
    if len(domain_parts) >= 2:
        second_level = domain_parts[-2]
        top_level = domain_parts[-1]
        if len(second_level) <= 2 and len(top_level) <= 2:
            return True

    return False

def is_auto_related(text):
    """检查文本是否与车企相关"""
    if not text:
        return False
    
    # 处理可能的列表输入
    if isinstance(text, list):
        # 如果是列表，检查每个元素
        for item in text:
            if is_auto_related(item):  # 递归调用
                return True
        return False
    
    # 确保是字符串
    if not isinstance(text, str):
        text = str(text)
        
    text_lower = text.lower()
    
    # 检查是否包含车企关键词
    for keyword in AUTO_COMPANY_KEYWORDS:
        if keyword.lower() in text_lower:
            return True
            
    return False

def get_geoip_info(ip):
    """获取IP地理位置信息"""
    # 检查缓存
    cached = geoip_cache.get(ip)
    if cached:
        return cached

    # 跳过私有IP
    if is_private_ip(ip):
        result = {"country": "Private", "city": "Private"}
        geoip_cache.set(ip, result)
        return result

    try:
        # 使用ipapi.co API
        response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5)
        if response.status_code == 200:
            data = response.json()
            country = data.get('country_name', 'Unknown')
            city = data.get('city', 'Unknown')
            result = {"country": country, "city": city}
            geoip_cache.set(ip, result)
            return result

        # 备用API: ipinfo.io
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        if response.status_code == 200:
            data = response.json()
            country = data.get('country', 'Unknown')
            city = data.get('city', 'Unknown')
            result = {"country": country, "city": city}
            geoip_cache.set(ip, result)
            return result
            
        # 备用API: ip-api.com
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                country = data.get('country', 'Unknown')
                city = data.get('city', 'Unknown')
                result = {"country": country, "city": city}
                geoip_cache.set(ip, result)
                return result
    except:
        pass

    result = {"country": "Unknown", "city": "Unknown"}
    geoip_cache.set(ip, result)
    return result

def get_org_from_domain_pattern(domain):
    """通过域名模式识别组织"""
    # 检查是否为CDN或云服务
    for org, pattern in CDN_PATTERNS.items():
        if re.match(pattern, domain):
            return org.capitalize() + " CDN/Cloud"

    # 提取主域名部分
    extracted = tldextract.extract(domain)
    main_domain = extracted.domain

    # 常见公司域名映射
    common_companies = {
        'baidu': 'Baidu',
        'ali': 'Alibaba',
        'taobao': 'Alibaba',
        'tmall': 'Alibaba',
        'qq': 'Tencent',
        'weixin': 'Tencent',
        'tencent': 'Tencent',
        'huawei': 'Huawei',
        'mi': 'Xiaomi',
        'xiaomi': 'Xiaomi',
        'jd': 'JD.com',
        'meituan': 'Meituan',
        'dianping': 'Meituan',
        'bytedance': 'ByteDance',
        'toutiao': 'ByteDance',
        'douyin': 'ByteDance',
        'netease': 'NetEase',
        '163': 'NetEase',
        'sina': 'Sina',
        'weibo': 'Sina',
        'sohu': 'Sohu',
        'iqiyi': 'iQiyi',
        'bilibili': 'Bilibili',
        'kuaishou': 'Kuaishou',
        'ctrip': 'Ctrip',
        'trip': 'Ctrip',
        'suning': 'Suning',
        'google': 'Google',
        'apple': 'Apple',
        'microsoft': 'Microsoft',
        'amazon': 'Amazon',
        'github': 'GitHub',
    }

    # 检查主域名是否在常见公司列表中
    if main_domain in common_companies:
        return common_companies[main_domain]

    # 尝试从域名中提取可能的公司名
    if len(main_domain) > 3 and not main_domain.isdigit():
        return main_domain.capitalize()

    return "Unknown"

def get_whois_info(domain):
    """获取域名的WHOIS信息"""
    # 检查缓存
    cached = whois_cache.get(domain)
    if cached:
        return cached

    # 首先尝试模式匹配
    org = get_org_from_domain_pattern(domain)
    if org != "Unknown":
        whois_cache.set(domain, org)
        return org

    # 然后尝试WHOIS查询
    try:
        w = whois.whois(domain)
        # 处理可能的列表返回值
        org_value = w.org
        if isinstance(org_value, list):
            org_value = org_value[0] if org_value else None
        
        if org_value:
            whois_cache.set(domain, org_value)
            return org_value
        
        # 同样处理registrar字段
        registrar_value = w.registrar
        if isinstance(registrar_value, list):
            registrar_value = registrar_value[0] if registrar_value else None
            
        if registrar_value:
            whois_cache.set(domain, registrar_value)
            return registrar_value
    except:
        pass

    # 尝试多个WHOIS API
    apis = [
        # WhoisXMLAPI (需要API密钥)
        lambda d: f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={WHOIS_API_KEY}&domainName={d}&outputFormat=JSON" if WHOIS_API_KEY else None,
        # Whois API (免费但有限制)
        lambda d: f"https://www.whois.com/whois/{d}",
    ]

    for api_url_gen in apis:
        try:
            api_url = api_url_gen(domain)
            if not api_url:
                continue

            response = requests.get(api_url, timeout=10, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })

            if response.status_code == 200:
                # 尝试解析JSON响应
                if 'json' in api_url or 'JSON' in api_url:
                    try:
                        data = response.json()
                        # 不同API的响应结构不同
                        org = data.get('WhoisRecord', {}).get('registrant', {}).get('organization') or \
                              data.get('registrant', {}).get('organization') or \
                              data.get('org') or \
                              data.get('organization')
                        if org and org != "N/A":
                            whois_cache.set(domain, org)
                            return org
                    except:
                        pass
                else:
                    # 解析HTML响应
                    html = response.text
                    # 尝试提取组织信息
                    patterns = [
                        r'Registrant Organization:\s*([^\n<]+)',
                        r'Organization:\s*([^\n<]+)',
                        r'org:\s*([^\n<]+)',
                        r'Registrant Name:\s*([^\n<]+)',
                    ]

                    for pattern in patterns:
                        match = re.search(pattern, html, re.IGNORECASE)
                        if match:
                            org = match.group(1).strip()
                            if org and org != "N/A" and len(org) > 2:
                                whois_cache.set(domain, org)
                                return org
        except:
            continue

    result = "Unknown"
    whois_cache.set(domain, result)
    return result

def process_ips(ip_list):
    """处理IP地址列表"""
    processed_ips = []
    
    for ip_item in tqdm(ip_list, desc="处理IP地址"):
        ip = ip_item.get('ip', '')
        source = ip_item.get('source', '')
        
        # 跳过私有IP
        if is_private_ip(ip):
            continue
            
        # 获取地理位置信息
        geo_info = get_geoip_info(ip)
        
        processed_ips.append({
            'ip': ip,
            'country': geo_info['country'],
            'city': geo_info['city'],
            'source_file': source
        })
    
    return processed_ips

def process_domains(domain_list):
    """处理域名列表"""
    processed_domains = []
    
    for domain_item in tqdm(domain_list, desc="处理域名"):
        domain = domain_item.get('domain', '')
        source = domain_item.get('source', '')
        
        # 跳过内部域名
        if is_internal_domain(domain):
            continue
            
        # 获取WHOIS信息
        org = get_whois_info(domain)
        
        # 检查是否与车企相关 - 这是关键修改点
        if not is_auto_related(domain) and not is_auto_related(org):
            continue  # 跳过与车企无关的域名
            
        # 获取IP和地理位置信息
        try:
            # 尝试解析域名获取IP
            ip = socket.gethostbyname(domain)
            geo_info = get_geoip_info(ip)
            country = geo_info['country']
            city = geo_info['city']
        except:
            country = "Unknown"
            city = "Unknown"
        
        processed_domains.append({
            'domain': domain,
            'country': country,
            'city': city,
            'owner': org,
            'source_file': source
        })
    
    return processed_domains

def process_secrets(secret_list):
    """处理密钥存储桶列表 - 直接输出所有内容"""
    processed_secrets = []
    
    for secret_item in tqdm(secret_list, desc="处理密钥存储桶"):
        # 直接保留原始内容，不进行任何处理
        processed_secrets.append({
            'secret': secret_item.get('secret', ''),
            'provider': secret_item.get('provider', ''),
            'source': secret_item.get('source', ''),
            'index': secret_item.get('index', '')
        })
    
    return processed_secrets

def process_cert_keys(cert_key_list):
    """处理证书密钥列表 - 直接输出所有内容"""
    processed_cert_keys = []
    
    for cert_key_item in tqdm(cert_key_list, desc="处理证书密钥"):
        # 直接保留原始内容，不进行任何处理
        processed_cert_keys.append({
            'content': cert_key_item.get('content', ''),
            'source': cert_key_item.get('source', ''),
            'index': cert_key_item.get('index', '')
        })
    
    return processed_cert_keys

def main():
    global WHOIS_API_KEY

    parser = argparse.ArgumentParser(description='数据分析工具 - 从step2_output.json读取数据并分析')
    parser.add_argument('-i', '--input', default='step2_output.json', help='输入JSON文件路径')
    parser.add_argument('-o', '--output', default='step3_output.json', help='输出JSON文件路径')
    parser.add_argument('--whois-api-key', help='WHOIS API密钥（如果需要）')
    parser.add_argument('--disable-online', action='store_true', help='禁用在线API查询')

    args = parser.parse_args()

    # 设置全局WHOIS API密钥
    WHOIS_API_KEY = args.whois_api_key

    # 读取输入文件
    if not os.path.exists(args.input):
        print(f"错误: 输入文件 {args.input} 不存在")
        return

    try:
        with open(args.input, 'r', encoding='utf-8') as f:
            input_data = json.load(f)
    except Exception as e:
        print(f"读取输入文件时出错: {e}")
        return

    # 如果禁用在线查询，使用默认值
    if args.disable_online:
        global get_geoip_info, get_whois_info
        get_geoip_info = lambda ip: {"country": "Unknown", "city": "Unknown"}
        get_whois_info = lambda domain: "Unknown"
        print("已禁用在线API查询")

    # 处理各个数据部分
    print("开始处理数据...")
    
    # 处理IP地址
    ips = input_data.get('ips', [])
    processed_ips = process_ips(ips)
    
    # 处理域名
    domains = input_data.get('domains', [])
    processed_domains = process_domains(domains)
    
    # 处理密钥存储桶
    secrets = input_data.get('secrets', [])
    processed_secrets = process_secrets(secrets)
    
    # 处理证书密钥
    cert_keys = input_data.get('cert_keys', [])
    processed_cert_keys = process_cert_keys(cert_keys)

    # 构建输出数据
    output_data = {
        'ips': processed_ips,
        'domains': processed_domains,
        'secrets': processed_secrets,  # 使用 secrets 而不是 buckets
        'cert_keys': processed_cert_keys
    }

    # 保存输出文件
    try:
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, ensure_ascii=False, indent=2)
        print(f"处理完成! 结果已保存到 {args.output}")
        
        # 输出统计信息
        print(f"发现公网IP地址数量: {len(processed_ips)}")
        print(f"发现车企相关域名数量: {len(processed_domains)}")
        print(f"发现密钥存储桶数量: {len(processed_secrets)}")
        print(f"发现证书密钥数量: {len(processed_cert_keys)}")
        
    except Exception as e:
        print(f"保存输出文件时出错: {e}")

if __name__ == '__main__':
    main()
