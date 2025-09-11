# by 符益铭
# 主入口点，胶水代码

import argparse
from os import path

import step1
import step2
import step3
import to_csv


def main(
    input_file: str,
    output_dir: str,
    skip_step1: bool = False,
    skip_step2: bool = False,
    skip_step3: bool = False,
):
    if not skip_step1:
        step1.main(input_file, output_dir if output_dir != "" else None)
    if not skip_step2:
        step2.main(output_dir, path.join(output_dir, "step2_output.json"))
    if not skip_step3:
        step3.main(
            path.join(output_dir, "step2_output.json"),
            path.join(output_dir, "step3_output.json"),
        )
    to_csv.main(path.join(output_dir, "step3_output.json"), output_dir)


if __name__ == "__main__":
    # 使用 argparse 创建一个漂亮的命令行帮助界面
    parser = argparse.ArgumentParser(description="固件分析工具")
    parser.add_argument("-f", "--file", required=True, help="输入的固件压缩包路径")
    parser.add_argument(
        "-o",
        "--output",
        default="output",
        help="分析结果的输出目录路径 （可选，默认为output）",
    )
    parser.add_argument("--skip-step1", action="store_true", help="跳过 step 1")
    parser.add_argument("--skip-step2", action="store_true", help="跳过 step 2")
    parser.add_argument("--skip-step3", action="store_true", help="跳过 step 3")
    args = parser.parse_args()

    # Enforce: to skip step2, user must also skip step1
    if args.skip_step2 and not args.skip_step1:
        parser.error(
            "--skip-step2 requires --skip-step1 （要跳过 step 2，必须同时跳过 step 1）"
        )

    # Enforce: to skip step3, user must also skip step1 and step2
    if args.skip_step3 and not args.skip_step2:
        parser.error(
            "--skip-step3 requires --skip-step2 （要跳过 step 3，必须同时跳过 step 2）"
        )

    input_file = args.file
    output_dir = args.output
    skip_step1 = args.skip_step1
    skip_step2 = args.skip_step2
    skip_step3 = args.skip_step3

    main(input_file, output_dir, skip_step1, skip_step2, skip_step3)
