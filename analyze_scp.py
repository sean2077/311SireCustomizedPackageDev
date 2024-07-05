import os
import xml.etree.ElementTree as ET
from collections import defaultdict

from rich.console import Console
from rich.table import Table


def merge_ranges(ranges):
    ranges = sorted(ranges)
    merged_ranges = []
    current_start = None
    current_end = None

    for start, end in ranges:
        if current_start is None:
            current_start = start
            current_end = end
        elif start <= current_end + 1:
            current_end = max(current_end, end)
        else:
            merged_ranges.append((current_start, current_end))
            current_start = start
            current_end = end

    if current_start is not None:
        merged_ranges.append((current_start, current_end))

    return merged_ranges


def analyze_scp_file(file_path):
    result = {"file": file_path, "author": "", "ranges": []}
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()

        author = root.find("PackageAuthor")
        author = author.text.strip() if author is not None else ""
        result["author"] = author

        ranges = []
        for custom_modify_item in root.findall(".//CustomModifyItem"):
            for code in custom_modify_item.findall(".//Code"):
                address = code.find("Address").text.strip().upper()
                enable_code = code.find("EnableCode").text.strip()
                disable_code = code.find("DisableCode").text

                # 暂时不考虑未填写 DisableCode 的情况，合格的 scp 不应该出现这种情况
                if disable_code is not None and not disable_code.replace("0", "").strip():
                    start_address = int(address, 16)
                    end_address = start_address + len(enable_code.split()) - 1
                    ranges.append((start_address, end_address))

        result["ranges"] = merge_ranges(ranges)
    except ET.ParseError:
        pass

    return result


def format_address(address):
    return f"{address:08X}"


def print_individual_results(file_results):
    table = Table(title="SCP新增的修改地址", show_lines=True)
    table.add_column("文件", style="cyan")
    table.add_column("作者", style="cyan")
    table.add_column("起始地址", style="cyan")
    table.add_column("终止地址", style="cyan")

    for result in file_results:
        file = result["file"]
        author = result["author"]
        ranges = result["ranges"]
        if len(ranges) == 0:
            table.add_row(file, author, "", "")
        else:
            start_addr_str = "\n".join(format_address(start) for start, _ in ranges)
            end_addr_str = "\n".join(format_address(end) for _, end in ranges)
            table.add_row(file, author, start_addr_str, end_addr_str)

    console = Console()
    console.print(table)
    print()


def print_summary_results(total_ranges):
    table = Table(title="新增修改地址总览")
    table.add_column("起始地址", style="magenta")
    table.add_column("终止地址", style="magenta")

    for start, end in total_ranges:
        table.add_row(format_address(start), format_address(end))

    console = Console()
    console.print(table)


def main():
    import argparse

    parser = argparse.ArgumentParser(description="分析 Sire 自定义包修改的内存地址范围")
    parser.add_argument("paths", nargs="+", help="文件或目录")
    args = parser.parse_args()

    file_paths = []
    for path in args.paths:
        if os.path.isfile(path) and path.endswith(".scp"):
            file_paths.append(path)
        elif os.path.isdir(path):
            # 递归遍历
            for root, _, files in os.walk(path):
                for file in files:
                    if file.endswith(".scp"):
                        file_paths.append(os.path.join(root, file))

    if not file_paths:
        print(f"No SCP files found in {args.path}")
        return

    file_results = []
    for file_path in file_paths:
        result = analyze_scp_file(file_path)
        file_results.append(result)
    # 按作者排序，因为同一个作者修改的地址可能是连续的
    file_results = sorted(file_results, key=lambda x: x["author"])
    print_individual_results(file_results)

    if len(file_results) > 2:
        total_ranges = []
        for result in file_results:
            total_ranges.extend(result["ranges"])
        total_ranges = merge_ranges(total_ranges)

        print_summary_results(total_ranges)


if __name__ == "__main__":
    main()
