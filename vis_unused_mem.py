import os
from collections import defaultdict

import matplotlib.pyplot as plt


def read_memory_ranges(file_path):
    ranges = []
    with open(file_path, "r") as file:
        for line in file:
            parts = line.strip().split(", ")
            start = int(parts[0].split(": ")[1], 16)
            end = int(parts[1].split(": ")[1], 16)
            ranges.append((start, end))
    return ranges


def group_ranges(ranges):
    grouped = defaultdict(list)
    for start, end in ranges:
        group = f"{start:08X}"[:3]  # 使用前三位数字作为分组依据
        grouped[group].append((start, end))
    return grouped


def visualize_memory_ranges(ranges):
    grouped_ranges = group_ranges(ranges)
    groups = sorted(grouped_ranges.keys())

    fig, ax = plt.subplots(figsize=(12, len(groups) * 0.5 + 1))

    for i, group in enumerate(groups):
        for start, end in grouped_ranges[group]:
            ax.barh(i, end - start, left=start, height=0.5, align="center")
            ax.text(start, i, f"{start:08X}", va="center", ha="right", fontsize=8)
            ax.text(end, i, f"{end:08X}", va="center", ha="left", fontsize=8)

    ax.set_yticks(range(len(groups)))
    ax.set_yticklabels([f"{group}XXXXX" for group in groups])
    ax.set_xlabel("Memory Address")
    ax.set_title("Memory Range Visualization")

    plt.tight_layout()
    plt.show()


# 使用示例
scrip_dir = os.path.dirname(os.path.realpath(__file__))
file_path = os.path.join(scrip_dir, "未使用的内存区间.txt")
memory_ranges = read_memory_ranges(file_path)
visualize_memory_ranges(memory_ranges)
