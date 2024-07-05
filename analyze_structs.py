import os
from collections import defaultdict

import matplotlib.pyplot as plt
import rich
import rich.table
from matplotlib.font_manager import FontProperties

# 本脚本所在目录
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


# 可视化
def visualize_arrays(arrays):
    # 使用支持中文的字体
    font = FontProperties(fname="C:/Windows/Fonts/simhei.ttf")  # 在Windows系统上使用SimHei字体

    fig, ax = plt.subplots()

    # 计算数组的总数
    num_arrays = len(arrays)

    # 设定x轴的位置，每个数组一个x值
    x_pos = range(num_arrays)

    # 画每个数组的起始和结束地址，并添加垂直虚线
    for i, (name, start, end) in enumerate(arrays):
        ax.plot([i, i], [start, end], marker="o", label=name)
        ax.hlines(start, 0, i, colors="gray", linestyles="dashed")
        ax.hlines(end, 0, i, colors="gray", linestyles="dashed")

    # 设置x轴的标签为数组名
    ax.set_xticks(x_pos)
    ax.set_xticklabels([name for name, start, end in arrays], fontproperties=font)

    # 设置y轴标签
    ax.set_ylabel("地址", fontproperties=font)

    # 添加标题
    ax.set_title("san11pk 结构体内存分布区间", fontproperties=font)

    # 保存图片
    plt.savefig("analyze_structs.png")

    # 显示图片
    plt.show()


def main():
    # 列出本脚本同目录下的所有txt文件
    txt_files = [f for f in os.listdir(SCRIPT_DIR) if f.endswith(".txt")]
    structs = []
    for txt_file in txt_files:
        with open(os.path.join(SCRIPT_DIR, txt_file), "r", encoding="utf-8") as f:
            struct = defaultdict(str)
            for line in f:
                if line.startswith("# struct_name_zh:"):
                    struct["struct_name_zh"] = line.split(":")[1].strip()
                if line.startswith("# start_addrs:"):
                    struct["start_addrs"] = line.split(":")[1].strip()
                if line.startswith("# end_addrs:"):
                    struct["end_addrs"] = line.split(":")[1].strip()
            for start, end in zip(struct["start_addrs"].split(","), struct["end_addrs"].split(",")):
                structs.append((struct["struct_name_zh"], start, end))

    # 按 start 地址排序
    structs.sort(key=lambda x: int(x[1], 16))

    # 用 rich 打印结果
    table = rich.table.Table(title="结构体列表")
    table.add_column("结构体名", style="cyan")
    table.add_column("起始地址", style="magenta")
    table.add_column("结束地址", style="green")
    for struct in structs:
        table.add_row(*struct)
    rich.print(table)

    # 将这些内存段可视化出来，并存为图片
    visualize_arrays(structs)


main()
