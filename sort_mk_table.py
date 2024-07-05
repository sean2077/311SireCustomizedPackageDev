#!python3
"""
排序 markdown 文件中的表格.

功能：
    - 支持多个表格，也支持全选和可选部分表格
    - 支持多列排序，每列均支持升序和降序排序
    - 支持自定义每列值的排序规则（默认按字符串排序）
    
依赖：
    pip install typer prettytable rich
"""

import logging
import os
from dataclasses import dataclass, field
from typing import Any, Callable

import typer
from prettytable import MARKDOWN, PrettyTable
from rich.logging import RichHandler
from typer import Typer

app = Typer(add_completion=False)

################################################################################
### logging
################################################################################


def _create_log(name: str = "", level="INFO", prefix=""):
    """创建 logger.

    log 等级:
        CRITICAL = 50
        FATAL = CRITICAL
        ERROR = 40
        WARNING = 30
        WARN = WARNING
        INFO = 20
        DEBUG = 10
        NOTSET = 0
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    if not logger.hasHandlers():
        h = RichHandler(level, rich_tracebacks=logger.level <= logging.DEBUG)
        h.setLevel(level)
        formatter = logging.Formatter("%(message)s", datefmt="%m/%d-%H:%M:%S")
        h.setFormatter(formatter)
        logger.addHandler(h)

    if prefix:

        class _AddPrefixAdapter(logging.LoggerAdapter):
            def process(self, msg, kwargs):
                return f"{prefix} {msg}", kwargs

        return _AddPrefixAdapter(logger, {})

    return logger


log = _create_log("sort_mk_table")


################################################################################
### MarkdownTableParser
################################################################################


@dataclass
class MarkdownTable:
    header: list[str] = field(default_factory=list)  # 表头
    rows: list[list[str]] = field(default_factory=list)  # 表格内容
    title: str = ""  # 表格标题, 用于标识表格位置, 默认为表格上方第一个非空行，也可自行指定，解析时会将该行下方的表格作为该标题的表格
    col_num: int = 0  # 列数


class MarkdownTableParser:
    """markdown 表格解析器"""

    _STATE_FINDING = 0  # 正在查找表格
    _STATE_FOUND = 1  # 已找到表格

    def __init__(self) -> None:
        self._tables: list[MarkdownTable] = []
        self._before_content = []  # 第一个表格前的内容
        self._after_contents: list[list[str]] = []  # 每个表格后的内容
        self._state = self._STATE_FINDING
        self._current_table = None
        self._current_table_index = -1
        self._table_title = None
        self._specific_table_titles = None

    def parse(self, mk_file: str, specific_table_titles: list[str] = None) -> list[MarkdownTable]:
        """解析 markdown 文件中的表格

        Args:
            mk_file (str): markdown 文件路径
            specific_table_titles (list[str], optional): 表格标题列表, 若不为空，则会在文件中留意 table_titles 中的标题，
                若找到 table_titles 中标题行，则该标题行下一个表格的名称设为该标题行，否则，表格的标题行设为 Table_{index}，
                其中 index 为该表在该文件中所有表格的序号。
                Defaults to None.

        Returns:
            list[MarkdownTable]: 解析的表格列表
        """
        self._reset()
        self._specific_table_titles = specific_table_titles

        with open(mk_file, "r", encoding="utf-8") as f:
            for line in f:
                self._parse_line(line)

        return self._tables

    def sort_tables(self, sort_by: str, *, specific_table_titles: list[str] = None, converters: dict[int, Callable[[str], Any] | str] = None):
        """排序 markdown 文件中的表格

        Args:
            sort_by (str): 排序的依据，要排序的列序号(从0开始); 支持多个排序字段，以逗号分隔; 如果序号加前缀 r 表示降序排序. 例: r0,1,2
            specific_table_titles (list[str], optional): 指定排序的表格，若不指定则全排序. Defaults to None.
            converters (dict): 指定每列的值转换函数，key 为列序号(int, 从0开始)，value 为转换函数(可以为str，会通过 eval 转换城函数). Defaults to None.
        """
        # 解析排序字段
        sort_indexes: list[tuple[int, bool]] = []
        for by in sort_by.split(","):
            by = by.strip()
            if by.startswith("r"):
                sort_indexes.append((int(by[1:]), True))
            else:
                sort_indexes.append((int(by), False))

        # 整理转换函数
        if converters and isinstance(converters, dict):
            converters = {k: _parse_converter(v) for k, v in converters.items()}

        # 排序表格
        for table in self._tables:
            if specific_table_titles and table.title not in specific_table_titles:
                continue
            # 从后往前排序
            for index, reverse in reversed(sort_indexes):
                if index >= table.col_num:
                    continue
                if converters and index in converters:
                    converter = converters[index]
                    table.rows.sort(key=lambda x: converter(x[index]), reverse=reverse)
                else:
                    table.rows.sort(key=lambda x: x[index], reverse=reverse)

    def write_file(self, mk_file: str):
        """将解析的表格写入文件"""
        with open(mk_file, "w", encoding="utf-8") as f:
            f.writelines(self._before_content)
            for i, table in enumerate(self._tables):
                tb = PrettyTable()
                tb.set_style(MARKDOWN)
                tb.align = "l"
                tb.field_names = table.header
                for row in table.rows:
                    tb.add_row(row)
                f.write(tb.get_string().replace("-|", " |"))  # 与 vscode markdown 插件格式化结果一致
                f.write("\n")
                f.writelines(self._after_contents[i])

    def reset(self):
        self._reset()

    def _reset(self):
        self._tables.clear()
        self._before_content.clear()
        self._after_contents.clear()
        self._state = self._STATE_FINDING
        self._current_table = None
        self._current_table_index = -1
        self._table_title = None
        self._specific_table_titles = None

    def _parse_line(self, line: str):
        if self._state == self._STATE_FINDING:
            return self._state_finding_table(line)
        if self._state == self._STATE_FOUND:
            return self._state_found_table(line)

        return None

    def _state_finding_table(self, line: str):
        # 先保存文件原文本
        if not self._tables:
            self._before_content.append(line)
        else:
            self._after_contents[self._current_table_index].append(line)

        line = line.strip()

        if self._specific_table_titles and line in self._specific_table_titles:
            self._table_title = line
            return

        if self._reach_table(line):
            self._state = self._STATE_FOUND

            # 去掉表格文本前两行
            if not self._tables:
                self._before_content.pop()
                header_line = self._before_content.pop()
            else:
                self._after_contents[self._current_table_index].pop()
                header_line = self._after_contents[self._current_table_index].pop()

            self._current_table = MarkdownTable()
            self._tables.append(self._current_table)
            self._after_contents.append([])
            self._current_table_index += 1

            self._current_table.header = [s.strip() for s in header_line.strip().strip("|").split("|")]
            self._current_table.title = self._table_title or f"Table_{self._current_table_index}"
            self._current_table.col_num = len(self._current_table.header)

            return

    def _state_found_table(self, line: str):
        items = [s.strip() for s in line.strip().strip("|").split("|")]

        if len(items) != self._current_table.col_num:
            self._state = self._STATE_FINDING
            self._table_title = None
            self._after_contents[self._current_table_index].append(line)
            return

        self._current_table.rows.append(items)

    @staticmethod
    def _reach_table(line: str) -> bool:
        """判断是否到达表格内容开始行"""
        return any(line.startswith(x) for x in ("| ---", "|--", "| :--", "|:--"))


# 一些常用的 converter，可以直接用这些 converter 的名称

int16 = lambda x: int(x, 16)


def _parse_converter(cvt_spec: str | Callable[[str], Any]) -> Callable[[str], Any]:
    if isinstance(cvt_spec, str):
        try:
            _cvt_func = eval(cvt_spec)
        except Exception as e:
            log.error(f"解析转换函数失败: {e}")
            _cvt_func = lambda x: x
    elif callable(cvt_spec):
        _cvt_func = cvt_spec
    else:
        _cvt_func = lambda x: x

    def _cvt(x: str):
        try:
            return 0, _cvt_func(x)
        except Exception as e:
            return 1, x
        # 转换失败的元素排序会靠后

    return _cvt


################################################################################
### Typer App Command
################################################################################


@app.command()
def sort_markdown_table(
    markdown_file: str = typer.Argument(..., help="markdown文件路径", show_default=False),
    sort_by: str = typer.Option(
        "0",
        "--sort-by",
        "-s",
        help='要排序的列序号(从0开始); 支持多个排序字段，以逗号分隔; 如果序号加前缀 r 表示降序排序. 例: -s "r0,1,2"',
        show_default=True,
        show_choices=False,
        case_sensitive=False,
    ),
    specific_table: list[str] = typer.Option(
        None,
        "--titles",
        "-t",
        help='指定要排序的表格，可以为该表格与上个表格之间可唯一标识的行内容, 如: -t "## 设施类型ID"',
        show_default=False,
    ),
    converters: list[str] = typer.Option(
        None,
        "--converters",
        "-c",
        help='列元素转换函数(col_index=function), 如: -c 0=int -c 1="lambda x: int(x, 16)"',
        show_default=False,
    ),
    save_as: str = typer.Option(
        None,
        "--save-as",
        "-o",
        help="保存排序后的 markdown 文件路径, 默认覆盖原文件",
        show_default=False,
    ),
):
    """
    排序 markdown 文件中的表格.

    功能：
        - 支持多个表格，也支持全选和可选部分表格
        - 支持多列排序，每列均支持升序和降序排序
        - 支持自定义每列值的排序规则（默认按字符串排序）

    依赖：
        pip install typer prettytable rich
    """

    parser = MarkdownTableParser()

    log.info(f"解析 markdown 文件: {markdown_file}")
    tbs = parser.parse(markdown_file, specific_table)
    log.info(f"解析到 {len(tbs)} 个表格")

    _converters = None
    if converters:
        _converters = {}
        for s in converters:
            kv = s.strip().split("=")
            if len(kv) != 2:
                log.error(f'忽略格式错误选项: "-c {s}", 正确格式为 "col_index=function", 如: -c 0=int -c 1="lambda x: int(x, 16)"')
                continue
            idx, cvt = kv
            _converters[int(idx)] = cvt

    log.info(f"排序表格: {sort_by=}, {specific_table=}, {converters=}")
    parser.sort_tables(sort_by, specific_table_titles=specific_table, converters=_converters)

    log.info(f"保存排序后的 markdown 文件: {save_as or markdown_file}")
    parser.write_file(save_as or markdown_file)


if __name__ == "__main__":
    app()
