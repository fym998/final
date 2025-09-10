# by 李金熙

# -----------------------------------------------------------------------------
# 导入我们需要的工具包
# -----------------------------------------------------------------------------
import argparse  # 用于处理命令行参数 (比如 -f 和 -o)
import os  # 用于处理文件和目录路径
import tarfile  # 用于解压 .tar, .tar.gz, .tgz 文件
import zipfile  # 用于解压 .zip 文件
import py7zr  # 用于解压 .7z 文件 (需要 pip install py7zr)
import logging  # 用于在控制台打印信息和日志
import shutil  # 用于更方便地移动和删除文件夹
from pathlib import Path  # 用更现代、更简单的方式处理文件路径
from collections import deque  # 一种特殊的列表，两头都能添加或删除，很适合用作任务队列
from typing import Dict, List  # 用于给函数参数和返回值添加类型提示，让代码更易读
from tqdm import tqdm  # 用于创建漂亮的进度条 (需要 pip install tqdm)

# -----------------------------------------------------------------------------
# 全局配置 (常量)
# 在这里修改脚本的行为会很方便
# -----------------------------------------------------------------------------

# 设置日志系统，让它在控制台打印出 INFO 级别以上的信息
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

# 定义我们认识的压缩包文件后缀。
# 把 .tar.gz 这样的长后缀也加进来，是为了后面能优先处理它们。
ARCHIVE_EXTENSIONS = {".tar.gz", ".tgz", ".zip", ".tar", ".gz", ".7z"}

# 定义哪些文件后缀被认为是“可读的文本文件”
TEXT_FILE_EXTENSIONS = {
    ".txt",
    ".xml",
    ".json",
    ".yaml",
    ".yml",
    ".conf",
    ".cfg",
    ".ini",
    ".log",
    ".sh",
    ".bat",
    ".properties",
    ".md",
    ".html",
    ".js",
    ".css",
}

# 定义哪些目录名下的文件被认为是“二进制可执行文件”
BINARY_DIRECTORIES = {"bin", "sbin"}


# -----------------------------------------------------------------------------
# 核心功能函数
# -----------------------------------------------------------------------------


def unarchive_file(archive_path: Path, dest_dir: Path) -> bool:
    """
    解压单个压缩包到指定的目录。

    这个函数是脚本的“工人”，负责具体的解压工作。
    它会根据不同的文件后缀，选择不同的工具（库）来解压。
    """
    try:
        # 确保目标目录存在，如果不存在就创建它
        dest_dir.mkdir(parents=True, exist_ok=True)
        name = archive_path.name

        # --- 解压逻辑：顺序很重要！---
        # 我们必须先检查最长的、最特殊的后缀，比如 .tar.gz。
        # 如果先检查 .gz，程序会把它解压成一个 .tar 文件，还需要再解压一次，效率低。
        # 所以这里的 if/elif 顺序是精心安排的。
        if name.endswith(".tar.gz") or name.endswith(".tgz"):
            with tarfile.open(archive_path, "r:gz") as t:
                t.extractall(dest_dir)
        elif name.endswith(".tar"):
            with tarfile.open(archive_path, "r:") as t:
                t.extractall(dest_dir)
        elif name.endswith(".zip"):
            with zipfile.ZipFile(archive_path, "r") as z:
                z.extractall(dest_dir)
        elif name.endswith(".7z"):
            with py7zr.SevenZipFile(archive_path, mode="r") as z:
                z.extractall(path=dest_dir)
        else:
            # 如果后缀不认识，就什么也不做，并返回 False
            return False

        # 如果成功解压，返回 True
        return True
    except Exception as e:
        # 如果在解压过程中发生任何错误（比如文件损坏），打印错误信息并返回 False
        logging.error(f"解压失败: {archive_path.name}. 错误: {e}")
        return False


def is_archive(file_path: Path) -> bool:
    """
    这是一个辅助函数，用来判断一个文件是不是我们想要处理的压缩包。
    它同样遵循“最长后缀优先”的原则。
    """
    # 优先检查最常见的复合后缀
    if file_path.name.endswith(".tar.gz") or file_path.name.endswith(".tgz"):
        return True
    # 然后再检查其他单一后缀
    if file_path.suffix in {".zip", ".tar", ".7z"}:
        return True
    # 如果都不是，就返回 False
    return False


def recursive_unarchive(root_path: Path):
    """
    递归地扫描并解压目录下的所有压缩包。

    这是脚本的第一个核心步骤。它会像剥洋葱一样，一层一层地解开所有压缩包，
    直到文件夹里再也找不到任何可以解压的文件为止。
    """
    # 创建一个任务队列，用来存放所有待解压的压缩包路径
    archive_queue = deque()

    # 步骤1: 初始扫描。遍历所有文件，把第一批发现的压缩包加入任务队列。
    for item in root_path.rglob("*"):
        if item.is_file() and is_archive(item):
            archive_queue.append(item.resolve())

    # 用一个集合(set)来记录已经处理过的压缩包，防止因为重复等原因陷入死循环
    processed_archives = set()

    # 步骤2: 循环处理。只要任务队列不为空，就一直工作。
    with tqdm(total=len(archive_queue), desc="递归解压", unit=" archive") as pbar:
        while archive_queue:
            # 从队列头部取出一个任务
            archive_path = archive_queue.popleft()
            pbar.update(1)  # 进度条+1
            if archive_path in processed_archives:
                continue

            pbar.set_postfix_str(archive_path.name, refresh=True)
            processed_archives.add(archive_path)

            # 智能地创建解压目录名。例如，把 "archive.tar.gz" 解压到 "archive/" 文件夹
            stem = archive_path.name
            for ext in [".tar.gz", ".tgz", ".zip", ".tar", ".7z"]:
                if stem.endswith(ext):
                    stem = stem[: -len(ext)]
                    break
            dest_dir = archive_path.parent / stem

            # 调用工人函数进行解压
            if unarchive_file(archive_path, dest_dir):
                # 解压成功后，删掉原来的压缩包，保持目录整洁
                archive_path.unlink()

                # 步骤3: 发现新任务。检查刚刚解压出来的文件夹里，有没有新的压缩包。
                new_archives_found = []
                for new_item in dest_dir.rglob("*"):
                    if (
                        new_item.is_file()
                        and is_archive(new_item)
                        and new_item.resolve() not in processed_archives
                    ):
                        new_archives_found.append(new_item.resolve())

                # 如果发现了新的压缩包，把它们加入任务队列，并更新进度条的总任务量
                if new_archives_found:
                    archive_queue.extend(new_archives_found)
                    pbar.total += len(new_archives_found)
                    pbar.refresh()


def classify_and_restructure(
    root_extraction_path: Path, final_output_dir: Path
) -> Dict[str, List[str]]:
    """
    对所有解压后的文件进行分类、移动和清理。

    这是脚本的第二个核心步骤。它会整理所有文件，把有用的（文本、APK、二进制）
    移动到新的、干净的文件夹里，同时记录下它们在固件里的原始路径。
    """
    # 步骤1: 创建最终的目标文件夹
    dest_dirs = {
        "text_files": final_output_dir / "text_files",
        "apk_files": final_output_dir / "apk_files",
        "binary_files": final_output_dir / "binary_files",
    }
    for dir_path in dest_dirs.values():
        dir_path.mkdir(parents=True, exist_ok=True)

    # 准备一个字典，用来存储每个文件的“原始路径”
    restored_paths = {"text_files": [], "apk_files": [], "binary_files": []}

    # 提前计算文件总数，为进度条做准备
    total_files = sum(len(files) for _, _, files in os.walk(root_extraction_path))
    print("\n--- 开始分类、移动并还原文件路径 ---")

    # 步骤2: 遍历所有解压出来的文件
    with tqdm(total=total_files, desc="文件重组", unit=" file") as pbar:
        for file_path in root_extraction_path.rglob("*"):
            if not file_path.is_file():
                continue  # 只处理文件，跳过文件夹
            pbar.update(1)

            # 判断文件属于哪个类别
            category = None
            if file_path.suffix == ".apk":
                category = "apk_files"
            elif file_path.suffix in TEXT_FILE_EXTENSIONS:
                category = "text_files"
            elif file_path.parent.name in BINARY_DIRECTORIES:
                category = "binary_files"

            # 计算文件在固件中的相对路径
            relative_path = file_path.relative_to(root_extraction_path)

            if category:
                # 如果是有用的文件：
                # 1. 移动它到对应的分类文件夹
                dest_path = dest_dirs[category] / file_path.name
                shutil.move(str(file_path), str(dest_path))

                # 2. 记录下它在固件中的原始路径
                restored_path = f"/{relative_path}"
                restored_paths[category].append(restored_path)
            else:
                # 如果是无用的文件：
                # 只有当它不是一个我们能识别的压缩包时，才报告丢弃
                if not is_archive(file_path):
                    logging.info(f"[清理] 丢弃非目标文件: /{relative_path}")

    # 步骤3: 所有有用的文件都移走后，整个临时解压目录就可以安全地删除了
    logging.info(f"\n清理临时解压目录及其剩余内容: {root_extraction_path}")
    shutil.rmtree(root_extraction_path)

    # 返回记录好的原始路径
    return restored_paths


def write_paths_to_files(restored_paths: Dict[str, List[str]], output_dir: Path):
    """
    将收集到的原始路径信息，分门别类地写入到三个 .txt 文件中。
    """
    for category, paths in restored_paths.items():
        output_file = output_dir / f"{category}.txt"
        logging.info(
            f"正在将 {len(paths)} 个 '{category}' 还原路径写入到: {output_file}"
        )
        # 写入前排序，让输出结果每次都一样，方便比较
        paths.sort()
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                for path in paths:
                    f.write(path + "\n")
        except IOError as e:
            logging.error(f"无法写入文件 {output_file}: {e}")


def process_firmware(firmware_path: str, output_path: str | None = None):
    """
    这是总指挥函数。
    它负责按正确的顺序调用所有其他函数，完成整个流程。
    """
    firmware_file = Path(firmware_path)
    if not firmware_file.is_file():
        raise FileNotFoundError(f"输入文件不存在: {firmware_path}")

    # 1. 决定最终的输出目录
    final_output_dir = (
        Path(output_path)
        if output_path
        else Path.cwd() / f"{firmware_file.stem}_output"
    )
    # 2. 创建一个临时的解压目录
    temp_extraction_dir = final_output_dir / "temp_extraction"
    final_output_dir.mkdir(parents=True, exist_ok=True)
    temp_extraction_dir.mkdir(exist_ok=True)

    logging.info(f"最终输出目录设定为: {final_output_dir.resolve()}")

    # 3. 执行：首次解压
    unarchive_file(firmware_file, temp_extraction_dir)
    # 4. 执行：递归解压
    recursive_unarchive(temp_extraction_dir)
    # 5. 执行：分类、重组和清理
    final_restored_paths = classify_and_restructure(
        temp_extraction_dir, final_output_dir
    )
    # 6. 执行：写入结果文件
    write_paths_to_files(final_restored_paths, final_output_dir)

    logging.info("所有任务完成！")


def main(firmware_path: str, output_path: str | None = None):
    try:
        # 调用总指挥函数，启动整个任务
        process_firmware(firmware_path, output_path)

        # 任务成功结束后，打印一个清晰的总结报告
        output_location = (
            Path(output_path)
            if output_path
            else Path.cwd() / f"{Path(firmware_path).stem}_output"
        )
        print("\n--- 子任务一执行成功 ---")
        print(
            f"\n所有有效文件已被重组到以下目录:\n"
            f"  - {output_location.resolve() / 'text_files'}\n"
            f"  - {output_location.resolve() / 'apk_files'}\n"
            f"  - {output_location.resolve() / 'binary_files'}"
        )
        print(
            f"\n还原后的固件内路径清单位于:\n"
            f"  - {output_location.resolve() / 'text_files.txt'}\n"
            f"  - {output_location.resolve() / 'apk_files.txt'}\n"
            f"  - {output_location.resolve() / 'binary_files.txt'}"
        )
    except Exception as e:
        # 如果在任何步骤出现无法处理的严重错误，打印它并退出
        logging.error(f"处理过程中发生严重错误: {e}", exc_info=True)


# -----------------------------------------------------------------------------
# 脚本的入口点
# 只有当这个 .py 文件被直接运行时，下面的代码才会执行
# 如果它被其他脚本作为模块导入，下面的代码不会执行
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    # 使用 argparse 创建一个漂亮的命令行帮助界面
    parser = argparse.ArgumentParser(
        description="固件分析工具 - 阶段一：文件提取、重组与路径还原"
    )
    parser.add_argument("-f", "--file", required=True, help="输入的固件压缩包路径")
    parser.add_argument("-o", "--output", help="分析结果的输出目录路径 (可选)")
    args = parser.parse_args()
    main(args.file, args.output)
