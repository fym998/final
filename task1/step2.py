import os
import sys
import json
from pathlib import Path
import subprocess
import tempfile

from step2_config import *

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
    # 检查是否为私有/保留 IP
    for pattern in PRIVATE_IP_PATTERNS:
        if pattern.match(ip):
            return False
    # 简单检查 IP 格式 (0-255)
    try:
        parts = [int(p) for p in ip.split(".")]
        if len(parts) != 4 or any(p < 0 or p > 255 for p in parts):
            return False
    except ValueError:
        return False
    return True


def decompile_apk_with_jadx(apk_path, output_dir):
    """
    使用 JADX 反编译 APK 文件到指定输出目录。
    返回 True 表示成功，False 表示失败。
    """
    if not JADX_CLI_PATH.exists():
        print(f"[Error] JADX CLI 未找到: {JADX_CLI_PATH}")
        return False

    cmd = [
        str(JADX_CLI_PATH),
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
        env = os.environ.copy()
        if JADX_BUNDLED_JRE_PATH.exists():
            env["JAVA_HOME"] = str(JADX_BUNDLED_JRE_PATH)

        result = subprocess.run(
            cmd, env=env, capture_output=True, text=True, timeout=300
        )
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


def extract_sensitive_from_text(content, source_path):
    """从文本内容中提取敏感信息"""
    findings = {"ips": [], "domains": [], "secrets": [], "cert_keys": []}

    full_text = (
        content if isinstance(content, str) else "\n".join(extract_strings(content))
    )

    # 1. 提取 IP
    for match in IPV4_PATTERN.findall(full_text):
        if is_public_ip(match):
            findings["ips"].append({"ip": match, "source": str(source_path)})

    # 2. 提取域名
    for match in DOMAIN_PATTERN.findall(full_text):
        if match.lower() not in ["localhost", "broadcasthost"]:
            findings["domains"].append({"domain": match, "source": str(source_path)})

    # 3. 提取云密钥
    for match in COMBINED_SECRET_REGEX.finditer(full_text):
        secret_str = match.group(0)
        provider = identify_secret_provider(secret_str)
        findings["secrets"].append(
            {"secret": secret_str, "provider": provider, "source": str(source_path)}
        )

    # 4. 提取证书和私钥内容
    for match in CERT_KEY_MARKER.finditer(full_text):
        key_block = match.group(0)
        findings["cert_keys"].append({"content": key_block, "source": str(source_path)})

    return findings


def process_apk_file(apk_path, rel_source, counter):
    """处理单个 APK 文件"""
    findings = {"ips": [], "domains": [], "secrets": [], "cert_keys": []}

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        print(f"[Info] 正在反编译 APK: {apk_path}")

        if not decompile_apk_with_jadx(apk_path, temp_path):
            return findings

        for file in temp_path.rglob("*"):
            if file.is_dir():
                continue

            try:
                decompiled_rel_path = file.relative_to(temp_path)
                source_identifier = f"{rel_source} -> {decompiled_rel_path}"

                if file.suffix.lower() == ".key":
                    # 格式: <原始APK文件名>_<反编译后相对路径中的文件名>.key
                    # 例如: app-release_lib_arm64-v8a_libnative-lib.key
                    apk_stem = Path(
                        rel_source
                    ).stem  # 获取 APK 文件名（不含路径和.apk后缀）
                    key_file_name = f"{apk_stem}_{decompiled_rel_path.name}"
                    safe_key_file_name = "".join(
                        c if c.isalnum() or c in ("_", "-", ".") else "_"
                        for c in key_file_name
                    )
                    output_key_file = (
                        Path.cwd() / safe_key_file_name
                    )  # Path.cwd() 获取当前工作目录
                    # 读取并保存 .key 文件的完整二进制内容
                    with open(file, "rb") as src_f:
                        key_content = src_f.read()

                    with open(output_key_file, "wb") as dst_f:
                        dst_f.write(key_content)

                    print(
                        f"[Info] 提取 .key 文件: {source_identifier} -> {output_key_file}"
                    )
                    continue

                if is_binary(file):
                    with open(file, "rb") as f:
                        data = f.read()
                    text_content = "\n".join(extract_strings(data))
                else:
                    with open(file, "r", encoding="utf-8", errors="ignore") as f:
                        text_content = f.read()

                file_findings = extract_sensitive_from_text(
                    text_content, source_identifier
                )

                for key in file_findings:
                    for item in file_findings[key]:
                        item["index"] = counter[key]
                        counter[key] += 1
                        findings[key].append(item)

            except Exception as e:
                print(f"[Warning] 处理反编译文件失败: {file}, 错误: {e}")
                continue

    return findings


# -------------------------
# 主处理函数
# -------------------------


def process_directory(root_dir):
    """遍历目录并处理所有文件"""
    root = Path(root_dir)
    all_findings = {"ips": [], "domains": [], "secrets": [], "cert_keys": []}
    counter = {"ips": 1, "domains": 1, "secrets": 1, "cert_keys": 1}

    for subdir_name in ["apk_files", "binary_files", "text_files"]:
        dir_path = root / subdir_name
        if not dir_path.exists():
            print(f"[Info] 目录不存在，跳过: {dir_path}")
            continue

        print(f"[Processing] 正在处理目录: {dir_path}")
        for file_path in dir_path.rglob("*"):
            if file_path.is_dir():
                continue

            rel_source = file_path.relative_to(root)

            try:
                if subdir_name == "apk_files" and file_path.suffix.lower() == ".apk":
                    apk_findings = process_apk_file(file_path, rel_source, counter)
                    for key in apk_findings:
                        all_findings[key].extend(apk_findings[key])
                    print(
                        f"[Info] APK 处理完成: {file_path}, 提取到 {sum(len(v) for v in apk_findings.values())} 项"
                    )
                else:
                    if is_binary(file_path):
                        with open(file_path, "rb") as f:
                            data = f.read()
                        text_content = "\n".join(extract_strings(data))
                    else:
                        with open(
                            file_path, "r", encoding="utf-8", errors="ignore"
                        ) as f:
                            text_content = f.read()

                    findings = extract_sensitive_from_text(text_content, rel_source)

                    for key in findings:
                        for item in findings[key]:
                            item["index"] = counter[key]
                            counter[key] += 1
                            all_findings[key].append(item)

            except Exception as e:
                print(f"[Error] 处理文件失败: {file_path}, 错误: {e}")
                continue

    # 去重函数内联
    def dedup(items, key_field):
        seen = set()
        unique = []
        for item in items:
            val = item[key_field]
            if val not in seen:
                seen.add(val)
                unique.append(item)
        return unique

    # 对结果去重
    all_findings["ips"] = dedup(all_findings["ips"], "ip")
    all_findings["domains"] = dedup(all_findings["domains"], "domain")
    all_findings["secrets"] = dedup(all_findings["secrets"], "secret")

    return all_findings


# -------------------------
# 主函数
# -------------------------

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("用法: python step2.py <解压后的根目录路径>")
        sys.exit(1)


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
    # print("下一步可运行 step3.py 进行 AI 清洗和车企关联过滤")

    return results


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("用法: python extract.py <解压后的根目录路径>")
        sys.exit(1)

    input_dir = sys.argv[1]
    main(input_dir)
