# by 符益铭
# 主入口点，胶水代码

import argparse

import step1
import step2
import step3

if __name__ == "__main__":
    # 使用 argparse 创建一个漂亮的命令行帮助界面
    parser = argparse.ArgumentParser(description="固件分析工具")
    parser.add_argument("-f", "--file", required=True, help="输入的固件压缩包路径")
    parser.add_argument("-a", "--automaker", required=True, help="车企名称")
    parser.add_argument(
        "-o", "--output", help="分析结果的输出目录路径 (可选，默认为当前目录)"
    )
    args = parser.parse_args()

    automaker = args.automaker
    input_file = args.file
    output_path = args.output

    # 依次调用三个步骤的 main 函数
    step1.main(input_file, output_path)
    step2_result = step2.main(output_path, output_path)
    step3.main(step2_result, automaker, output_path)
