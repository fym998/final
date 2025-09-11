# by 李皓然

import os
import re
import sys
import json
from pathlib import Path
import string
import subprocess
import tempfile

# -------------------------
# 配置与正则表达式定义
# -------------------------
# 配置 JADX 路径
JADX_CLI_PATH = r"D:\jadx 1.5.2\bin\jadx.bat"
JADX_BUNDLED_JRE_PATH = r"D:\jadx_gui 1.5.2\jre"

# 可打印字符（用于模拟 strings 命令）
PRINTABLE = set(bytes(string.printable, "ascii"))

# IPv4 正则（过滤本地/私有 IP）
IPV4_PATTERN = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
PRIVATE_IPS = [
    re.compile(r"^127\."),
    re.compile(r"^10\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^172\.(1[6-9]|2[0-9]|3[0-1])\."),
]

# 域名白名单
WHITELISTED_TLDS = [
    "com",
    "cn",
    "net",
    "org",
    "gov",
    "edu",
    "info",
    "biz",
    "name",
    "pro",
    "museum",
    "mobi",
    "asia",
    "tel",
    "io",
    "app",
    "dev",
    "tech",
    "site",
    "auto",
    "car",
    "cars",
    "sport",
    "hk",
    "tw",
    "jp",
    "kr",
    "sg",
    "de",
    "fr",
]

# 域名正则
DOMAIN_PATTERN = re.compile(
    r"(?<![a-zA-Z0-9.-])"
    r"((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:"
    + "|".join(WHITELISTED_TLDS)
    + r"))"
    r"(?![a-zA-Z0-9.-])",
    re.IGNORECASE,
)

# 存储桶相关关键词（S3, OSS, COS, GCS 等）
BUCKET_PATTERNS = [
    re.compile(
        r"https?://[a-zA-Z0-9][a-zA-Z0-9.-]{2,61}\.[a-zA-Z0-9][a-zA-Z0-9.-]*\.s3\.([a-zA-Z0-9-]+\.){0,2}amazonaws\.com(\.cn)?"
    ),
    re.compile(
        r"https?://s3\.([a-zA-Z0-9-]+\.){0,2}amazonaws\.com(\.cn)?/[a-zA-Z0-9][a-zA-Z0-9._-]+"
    ),
    re.compile(r"\bs3://[a-zA-Z0-9][a-zA-Z0-9._-]{2,61}\b"),
    # Aliyun OSS
    re.compile(
        r"\b[a-zA-Z0-9][a-zA-Z0-9.-]{2,61}\.oss-[a-zA-Z0-9-]+\.aliyuncs\.com(\.cn)?\b"
    ),
    # Tencent COS
    re.compile(r"\b[a-zA-Z0-9][a-zA-Z0-9.-]{2,61}\.cos\.[\w.-]+\.myqcloud\.com\b"),
    # Google Cloud Storage
    re.compile(r"\bgs://[a-zA-Z0-9][a-zA-Z0-9._-]{2,61}\b"),
    re.compile(r"\b[a-zA-Z0-9][a-zA-Z0-9._-]{2,61}\.storage\.googleapis\.com\b"),
]

# 证书/密钥标识
CERT_KEY_MARKER = re.compile(
    r"(?s)-----BEGIN (?:RSA )?(?:PRIVATE KEY|CERTIFICATE|EC PRIVATE KEY|DSA PRIVATE KEY|PUBLIC KEY|OPENSSH PRIVATE KEY)-----(?:.(?<!-----END ))*?-----END (?:RSA )?(?:PRIVATE KEY|CERTIFICATE|EC PRIVATE KEY|DSA PRIVATE KEY|PUBLIC KEY|OPENSSH PRIVATE KEY)-----"
)

# 云服务商域名关键词（用于第三步AI清洗预标记）
CLOUD_PROVIDER_DOMAINS = [
    "amazonaws.com",
    "aliyuncs.com",
    "myqcloud.com",
    "googleapis.com",
    "azure.com",
    "cloudfront.net",
]


# -------------------------
# 工具函数
# -------------------------


def is_binary(path):
    """判断文件是否为二进制文件"""
    try:
        with open(path, "rb") as f:
            chunk = f.read(1024)
            if not chunk:
                return False
            if b"\x00" in chunk:
                return True
            # 统计非可打印字符比例
            non_printable_ratio = sum(1 for b in chunk if b not in PRINTABLE) / len(
                chunk
            )
            return non_printable_ratio > 0.3
    except Exception as e:
        print(f"[Warning] 无法读取文件: {path}, 错误: {e}")
        return True


def extract_strings(data, min_length=4):
    """从 bytes 中提取可打印字符串"""
    if isinstance(data, str):
        data = data.encode("utf-8", errors="ignore")
    printable = string.printable
    result = []
    s = ""
    for b in data:
        c = chr(b)
        if c in printable:
            s += c
        else:
            if len(s) >= min_length:
                result.append(s)
            s = ""
    if len(s) >= min_length:
        result.append(s)
    return result


def is_public_ip(ip):
    """判断是否为公网 IP"""
    for pattern in PRIVATE_IPS:
        if pattern.match(ip):
            return False

    parts = ip.split(".")
    for part in parts:
        if len(part) > 1 and part.startswith("0"):  # "01", "001", "010"
            return False
    try:
        parts_int = [int(p) for p in parts]
        if any(p < 0 or p > 255 for p in parts_int):
            return False
    except:
        return False
    return True


def decompile_apk_with_jadx(apk_path, output_dir):
    """
    使用 JADX 反编译 APK 文件到指定输出目录。
    返回 True 表示成功，False 表示失败。
    """
    if not Path(JADX_CLI_PATH).exists():
        print(f"[Error] JADX CLI 未找到: {JADX_CLI_PATH}")
        return False

    # 构建命令
    # 使用 --no-imports 避免生成 import 语句（减少噪音，不影响我们找字符串）
    # 使用 --deobf 启用反混淆（如果适用）
    # 使用 --deobf-min 2 和 --deobf-max 64 设置反混淆名称长度
    # 使用 --log-level ERROR 只显示错误
    cmd = [
        JADX_CLI_PATH,
        "--no-imports",
        "--deobf",
        "--deobf-min",
        "2",
        "--deobf-max",
        "64",
        "--log-level",
        "ERROR",
        "--output-dir",
        str(output_dir),
        str(apk_path),
    ]

    try:
        # 如果指定了捆绑的 JRE，则设置 JAVA_HOME
        if JADX_BUNDLED_JRE_PATH and Path(JADX_BUNDLED_JRE_PATH).exists():
            env = os.environ.copy()
            env["JAVA_HOME"] = JADX_BUNDLED_JRE_PATH
            result = subprocess.run(
                cmd, env=env, capture_output=True, text=True, timeout=300
            )  # 5分钟超时
        else:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        if result.returncode != 0:
            print(f"[Error] JADX 反编译失败: {apk_path}")
            print(f"  STDERR: {result.stderr}")
            return False
        else:
            print(f"[Info] JADX 反编译成功: {apk_path} -> {output_dir}")
            return True

    except subprocess.TimeoutExpired:
        print(f"[Error] JADX 反编译超时: {apk_path}")
        return False
    except Exception as e:
        print(f"[Error] JADX 反编译异常: {apk_path}, 错误: {e}")
        return False


def process_apk_file(apk_path, rel_source, counter):
    """
    处理单个 APK 文件：反编译并扫描其源代码。
    返回提取到的 findings 字典。
    """
    findings = {"ips": [], "domains": [], "buckets": [], "cert_keys": []}

    # 创建临时目录用于存放反编译结果
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        print(f"[Info] 正在反编译 APK: {apk_path}")

        success = decompile_apk_with_jadx(apk_path, temp_path)
        if not success:
            return findings  # 返回空结果

        # 递归遍历反编译目录下的所有 .java 文件
        for java_file in temp_path.rglob("*.java"):
            try:
                with open(java_file, "r", encoding="utf-8", errors="ignore") as f:
                    java_content = f.read()

                # 从 Java 源码中提取敏感信息
                # 注意：source 路径标记为原始 APK 文件 + Java 文件的相对路径，便于追踪
                java_rel_path = java_file.relative_to(temp_path)
                source_identifier = f"{rel_source} -> {java_rel_path}"

                java_findings = extract_sensitive_from_text(
                    java_content, source_identifier
                )

                # 合并结果并添加序号
                for key in java_findings:
                    for item in java_findings[key]:
                        item["index"] = counter[key]
                        counter[key] += 1
                        findings[key].append(item)

            except Exception as e:
                print(f"[Warning] 读取或处理 Java 文件失败: {java_file}, 错误: {e}")
                continue

    return findings


# -------------------------
# 主提取函数
# -------------------------


def extract_sensitive_from_text(content, source_path):
    findings = {"ips": [], "domains": [], "buckets": [], "cert_keys": []}

    # 提取原始文本行（如果是字符串）
    if isinstance(content, bytes):
        text_lines = extract_strings(content)
        full_text = "\n".join(text_lines)
    else:
        full_text = content
        try:
            text_lines = content.splitlines()
        except:
            text_lines = []

    # 1. 提取 IP
    for match in IPV4_PATTERN.findall(full_text):
        if is_public_ip(match):
            findings["ips"].append({"ip": match, "source": str(source_path)})

    # 2. 提取域名
    for match in DOMAIN_PATTERN.findall(full_text):
        # 过滤常见局域网域名
        if match.lower() in ["localhost", "broadcasthost"]:
            continue
        findings["domains"].append({"domain": match, "source": str(source_path)})

    # 3. 提取存储桶
    for bucket_pattern in BUCKET_PATTERNS:
        for match in bucket_pattern.findall(full_text):
            findings["buckets"].append({"bucket": match, "source": str(source_path)})

    # 4. 提取证书和私钥内容
    for match in CERT_KEY_MARKER.finditer(full_text):  # 使用 finditer
        key_block = match.group(0)
        findings["cert_keys"].append({"content": key_block, "source": str(source_path)})

    return findings


# -------------------------
# 遍历目录处理文件
# -------------------------


def process_directory(root_dir):
    root = Path(root_dir)
    all_findings = {"ips": [], "domains": [], "buckets": [], "cert_keys": []}
    counter = {"ips": 1, "domains": 1, "buckets": 1, "cert_keys": 1}

    for subdir in ["apk_files", "binary_files", "text_files"]:
        dir_path = root / subdir
        if not dir_path.exists():
            print(f"[Info] 目录不存在，跳过: {dir_path}")
            continue

        print(f"[Processing] 正在处理目录: {dir_path}")
        for file_path in dir_path.rglob("*"):
            if file_path.is_dir():
                continue

            rel_source = file_path.relative_to(root)

            try:
                if subdir == "apk" and file_path.suffix.lower() == ".apk":
                    # --- 专门处理 APK 文件 ---
                    apk_findings = process_apk_file(file_path, rel_source, counter)
                    # 合并结果
                    for key in apk_findings:
                        all_findings[key].extend(apk_findings[key])
                    # counter 已在 process_apk_file 内部更新，无需在此处重复更新
                    print(
                        f"[Info] APK 处理完成: {file_path}, 提取到 {sum(len(v) for v in apk_findings.values())} 项"
                    )
                else:
                    if is_binary(file_path):
                        # 二进制文件：读取 bytes 并提取 strings
                        with open(file_path, "rb") as f:
                            data = f.read()
                        text_content = "\n".join(extract_strings(data))
                    else:
                        # 文本文件：直接读取
                        with open(
                            file_path, "r", encoding="utf-8", errors="ignore"
                        ) as f:
                            text_content = f.read()

                    # 提取敏感信息
                    findings = extract_sensitive_from_text(text_content, rel_source)

                    # 添加序号并合并
                    for key in findings:
                        for item in findings[key]:
                            item["index"] = counter[key]
                            counter[key] += 1
                            all_findings[key].append(item)

            except Exception as e:
                print(f"[Error] 处理文件失败: {file_path}, 错误: {e}")
                continue

    def dedup_by_field(findings_list, field_name):
        seen = {}
        unique_items = []
        for item in findings_list:
            key_value = item[field_name]  # 如 item['ip'] 或 item['domain']
            if key_value not in seen:
                seen[key_value] = True
                unique_items.append(item)
        return unique_items

    # 对 IPs 去重
    if all_findings["ips"]:
        print(f"去重前 IPs 数量: {len(all_findings['ips'])}")
        all_findings["ips"] = dedup_by_field(all_findings["ips"], "ip")
        print(f"去重后 IPs 数量: {len(all_findings['ips'])}")

    # 对 Domains 去重
    if all_findings["domains"]:
        print(f"去重前 Domains 数量: {len(all_findings['domains'])}")
        all_findings["domains"] = dedup_by_field(all_findings["domains"], "domain")
        print(f"去重后 Domains 数量: {len(all_findings['domains'])}")

    return all_findings


# -------------------------
# 主函数
# -------------------------


def main(input_dir, output_path="step2_output.json"):
    if not os.path.exists(input_dir):
        print(f"错误: 目录不存在: {input_dir}")
        sys.exit(1)

    print(f"开始第二步处理：从 {input_dir} 提取敏感信息...")
    results = process_directory(input_dir)

    # 输出统计
    print("\n[提取完成] 结果统计:")
    for k, v in results.items():
        print(f"  {k}: {len(v)} 项")

    # 保存为中间 JSON 文件（供 step3 使用）
    output_file = output_path
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    print(f"\n✅ 敏感信息已提取完成，保存为: {output_file}")
    # print("下一步可运行 step3_ai_filter.py 进行 AI 清洗和车企关联过滤")

    return results


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("用法: python extract.py <解压后的根目录路径>")
        sys.exit(1)

    input_dir = sys.argv[1]
    main(input_dir)
