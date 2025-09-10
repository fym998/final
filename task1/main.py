# by 符益铭
# 主入口点，胶水代码

import argparse

import step1
import step2

if __name__ == "__main__":
    # 使用 argparse 创建一个漂亮的命令行帮助界面
    parser = argparse.ArgumentParser(description="固件分析工具")
    parser.add_argument("-f", "--file", required=True, help="输入的固件压缩包路径")
    parser.add_argument("-o", "--output", help="分析结果的输出目录路径 (可选)")
    args = parser.parse_args()
    step1.main(args.file, args.output)
    step2.main(args.output, args.output)
