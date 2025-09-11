import re
import string
from pathlib import Path

# -------------------------
# 全局配置
# -------------------------

# JADX 路径配置
JADX_CLI_PATH = Path(r"C:\Users\16378\Desktop\shixi\jadx\jadx 1.5.2\bin\jadx.bat")
JADX_BUNDLED_JRE_PATH = Path(r"C:\Users\16378\Desktop\shixi\jadx\jadx_gui 1.5.2\jre")

# 可打印字符集 (用于模拟 strings 命令)
PRINTABLE = set(bytes(string.printable, 'ascii'))

# -------------------------
# 正则表达式模式
# -------------------------

# IPv4 正则 (过滤本地/私有 IP)
IPV4_PATTERN = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')

# 私有/保留 IP 段正则
PRIVATE_IP_PATTERNS = [
    re.compile(r'^127\.'),
    re.compile(r'^10\.'),
    re.compile(r'^192\.168\.'),
    re.compile(r'^172\.(1[6-9]|2[0-9]|3[0-1])\.'),
]

# 域名白名单顶级域
WHITELISTED_TLDS = [
    'com', 'cn', 'net', 'org', 'gov', 'edu', 'info', 'biz', 'name', 'pro',
    'museum', 'mobi', 'asia', 'tel', 'io', 'app', 'dev', 'tech', 'site',
    'auto', 'car', 'cars', 'sport', 'hk', 'tw', 'jp', 'kr', 'sg', 'de', 'fr'
]

# 域名正则
DOMAIN_PATTERN = re.compile(
    r'(?<![a-zA-Z0-9.-])'
    r'((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:' + '|'.join(WHITELISTED_TLDS) + r'))'
    r'(?![a-zA-Z0-9.-])',
    re.IGNORECASE
)

# 云厂商密钥
CLOUD_SECRET_RULES = {
    "Amazon Web Services (AWS)": re.compile(r'AKIA[A-Z0-9]{16}'),
    "Alibaba Cloud (阿里云)": re.compile(r'LTAI[a-zA-Z0-9]{12,20}'),
    "Tencent Cloud (腾讯云)": re.compile(r'AKID[a-zA-Z0-9]{13,20}'),
    "Google Cloud Platform (GCP)": re.compile(r'GOOG[\w\W]{10,30}'),
    "Microsoft Azure": re.compile(r'AZ[A-Za-z0-9]{34,40}'),
    "Oracle Cloud": re.compile(r'OCID[A-Za-z0-9]{10,40}'),
    "Baidu Cloud (百度云)": re.compile(r'AK[A-Za-z0-9]{10,40}'),
    "JD Cloud (京东云)": re.compile(r'JDC_[A-Z0-9]{28,32}'),
    "Volcengine (火山引擎)": re.compile(r'AKLT[a-zA-Z0-9-_]{0,252}'),
    "QingCloud (青云)": re.compile(r'QY[A-Za-z0-9]{10,40}'),
    "Kingsoft Cloud (金山云)": re.compile(r'AKLT[a-zA-Z0-9-_]{16,28}'),
    "China Unicom Cloud (联通云)": re.compile(r'LTC[A-Za-z0-9]{10,60}'),
    "China Mobile Cloud (移动云)": re.compile(r'YD[A-Za-z0-9]{10,60}'),  
    "China Telecom Cloud (电信云)": re.compile(r'CTC[A-Za-z0-9]{10,60}'),
    "YiYunTong Cloud (一云通)": re.compile(r'YYT[A-Za-z0-9]{10,60}'),
    "Yonyou Cloud (用友云)": re.compile(r'YY[A-Za-z0-9]{10,40}'),
    "G-Core Labs": re.compile(r'gcore[A-Za-z0-9]{10,30}')
}

# 合并所有密钥正则，用于快速扫描
COMBINED_SECRET_REGEX = re.compile("|".join(f"({rule.pattern})" for rule in CLOUD_SECRET_RULES.values()))

def identify_secret_provider(secret_string):
    """根据匹配到的密钥字符串，识别出具体的云厂商。"""
    for provider, rule in CLOUD_SECRET_RULES.items():
        if rule.fullmatch(secret_string):
            return provider
    return "Unknown Provider"

# 证书/密钥标识
CERT_KEY_MARKER = re.compile(
    r'(?s)-----BEGIN (?:RSA )?(?:PRIVATE KEY|CERTIFICATE|EC PRIVATE KEY|DSA PRIVATE KEY|PUBLIC KEY|OPENSSH PRIVATE KEY)-----(?:.(?<!-----END ))*?-----END (?:RSA )?(?:PRIVATE KEY|CERTIFICATE|EC PRIVATE KEY|DSA PRIVATE KEY|PUBLIC KEY|OPENSSH PRIVATE KEY)-----'
)