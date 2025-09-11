# by 符益铭

import argparse
import csv
import json
from os import path


def write_csv_table(output_path: str, table: list[dict], headers: list[str]):
    """将数据写入CSV文件"""
    with open(output_path, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=headers, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(table)


def write_ip_table(ips: list[dict], output_dir: str):
    """将IP地址写入CSV文件"""
    headers = ["ip", "country", "city", "source_file"]
    output_path = path.join(output_dir, "ips.csv")
    write_csv_table(output_path, ips, headers)


def write_domain_table(domains: list[dict], output_dir: str):
    """将域名写入CSV文件"""
    headers = ["domain", "owner", "country", "city", "source_file"]
    output_path = path.join(output_dir, "domains.csv")
    write_csv_table(output_path, domains, headers)


def write_secret_table(secrets: list[dict], output_dir: str):
    """将存储桶信息写入CSV文件"""
    headers = ["provider", "secret", "source"]
    output_path = path.join(output_dir, "secrets.csv")
    write_csv_table(output_path, secrets, headers)


def write_certificate_table(certificates: list[dict], output_dir: str):
    """将证书信息写入CSV文件"""
    headers = ["content", "source"]
    output_path = path.join(output_dir, "certificates.csv")
    write_csv_table(output_path, certificates, headers)


def main(
    input_file: str,
    output_dir: str,
):
    """将各表格写入CSV文件"""
    input = json.load(open(input_file, "r", encoding="utf-8"))
    ips = input.get("ips", [])
    domains = input.get("domains", [])
    secrets = input.get("secrets", [])
    certificates = input.get("cert_keys", [])
    write_ip_table(ips, output_dir)
    write_domain_table(domains, output_dir)
    write_secret_table(secrets, output_dir)
    write_certificate_table(certificates, output_dir)
    print(f"CSV files have been written to {output_dir}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="将数据写入CSV文件")
    parser.add_argument(
        "-d",
        "--dir",
        default=".",
        help="输出目录路径 (可选，默认为当前目录）",
    )
    parser.add_argument(
        "-f",
        "--file",
        default="step3_output.json",
        help="输入文件路径（可选，默认为 step3_output.json）",
    )
    args = parser.parse_args()

    output_dir = args.dir
    input_file = args.file
    main(
        input_file,
        output_dir,
    )
