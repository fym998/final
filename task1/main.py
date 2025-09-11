# by 符益铭
# 主入口点，胶水代码

import argparse
from os import path

import step1
import step2
import step3
import to_csv


def main(input_file: str, output_dir: str = "", skip_step1: bool = False):
    if not skip_step1:
        step1.main(input_file, output_dir if output_dir != "" else None)
    step2.main(output_dir, path.join(output_dir, "step2_output.json"))
    step3_result = step3.main(
        path.join(output_dir, "step2_output.json"),
        path.join(output_dir, "step3_output.json"),
    )
    to_csv.main(step3_result, output_dir)


if __name__ == "__main__":
    # 使用 argparse 创建一个漂亮的命令行帮助界面
    parser = argparse.ArgumentParser(description="固件分析工具")
    parser.add_argument("-f", "--file", required=True, help="输入的固件压缩包路径")
    parser.add_argument(
        "-o",
        "--output",
        default="output",
        help="分析结果的输出目录路径 (可选，默认为output）",
    )
    parser.add_argument("--skip-step1", action="store_true", help="跳过step 1")
    args = parser.parse_args()

    input_file = args.file
    output_dir = args.output
    skip_step1 = args.skip_step1

    main(input_file, output_dir, skip_step1)
