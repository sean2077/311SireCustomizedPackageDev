#!python
import os
import shutil
from collections import defaultdict

ROOT_DIR = "tutorial"
ASSETS_DIR = os.path.join(ROOT_DIR, ".assets")
TRASH_DIR = os.path.join(ROOT_DIR, ".trash")


# 遍历 ROOT_DIR 目录下的所有 md 文件，记录每个文件被引用的次数
_refs = defaultdict(int)
for root, dirs, files in os.walk(ROOT_DIR):
    for file in files:
        if file.endswith(".md"):
            with open(os.path.join(root, file), "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    # find first ![ in line
                    r = line.find("![")
                    if r == -1:
                        continue
                    line = line[r:]
                    if line.startswith("!["):
                        file_name = line.split("]")[1].strip("()")
                        file_name = file_name.removeprefix("./.assets/")
                        _refs[file_name] += 1


if not os.path.exists(TRASH_DIR):
    os.makedirs(TRASH_DIR)

for file_name in os.listdir(ASSETS_DIR):
    file_path = os.path.join(ASSETS_DIR, file_name)
    if os.path.isfile(file_path) and _refs[file_name] == 0:
        print(f"Moving {file_name} to .trash")
        shutil.move(file_path, os.path.join(TRASH_DIR, file_name))
