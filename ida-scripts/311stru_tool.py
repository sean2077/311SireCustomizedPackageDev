"""
san11pk's IDA Struct Tool
"""

import os
import re
import sys
from datetime import datetime

import prettytable
from attrs import define, field

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))

STRUCTS_FILE = os.path.join(os.path.dirname(SCRIPT_DIR), "material", "结构体汇总.md")


FORCE_UPDATE_STRUCT_ARRAYS = False  # 强制更新结构体数组(包含链表节点)
DO_NOT_MAKE_ARRAY = True  # 不创建数组，而是创建多个结构体

LINKED_LIST_STRUCT_NAME = {  # key: struct_name, value: node_name
    "struct_person_list": "struct_person_node",
    "struct_building_list": "struct_building_node",
}

#######################################################################################################
###                                            Utils                                                ###
#######################################################################################################


def get_now_time() -> str:
    """获取当前时间，形如 2020-06-06 14:00:00"""
    now = datetime.now()
    return now.strftime("%Y-%m-%d %H:%M:%S")


def format_address(addr: int) -> str:
    """格式化地址"""
    return f"{addr:08x}"


def int16(x: str) -> int:
    return int(x, 16)


def get_pure_data_type(data_type: str) -> str:
    """获取去掉 [], *, () 的 data_type"""
    return data_type.split("[")[0].split("*")[0].split("(")[0].strip()


def is_struct_type(data_type: str) -> bool:
    """检查数据类型是否是结构体类型"""
    return data_type.startswith("struct_") or data_type.startswith("struc_")


#######################################################################################################
###                                     结构体文件读写相关                                             ###
#######################################################################################################

_STRUCT_TABLE_HEADER = ["offset", "nbytes", "data_type", "field_name", "field_comment"]


def _set_hook(instance, attrib, new_value):
    c = attrib.converter
    if c:
        new_value = c(new_value)
    if getattr(instance, attrib.name) != new_value:
        instance._mark_modified()
    return new_value


@define
class StructField:
    """结构体字段"""

    offset: int = field(on_setattr=_set_hook)
    size: int = field(on_setattr=_set_hook)  # 字段大小
    data_type: str = field(on_setattr=_set_hook)  # 数据类型
    name: str = field(on_setattr=_set_hook)  # 字段名(带前缀)
    comment: str = field(on_setattr=_set_hook)  # 字段注释

    _is_array: bool = field(default=False, init=False, repr=False)  # 是否是数组
    _is_ptr: bool = field(default=False, init=False, repr=False)  # 是否是指针
    _pure_data_type: str = field(default="", init=False, repr=False)  # 去掉 [], *, () 的 data_type
    _pure_name: str = field(default="", init=False, repr=False)  # 去掉前缀(fld_xx_ 或 field_XX)的字段名

    _modified: bool = field(default=False, init=False, repr=False)  # 是否被修改

    def _mark_modified(self):
        object.__setattr__(self, "_modified", True)

    def __attrs_post_init__(self):
        self._is_array = "[" in self.data_type
        self._is_ptr = self.data_type in ("pointer", "address", "pointer32") or "*" in self.data_type
        self._pure_data_type = get_pure_data_type(self.data_type)
        _pure_name = self.name
        if self.name.startswith(f"fld_{self.offset:x}_"):
            _pure_name = self.name.removeprefix(f"fld_{self.offset:x}_")
        elif self.name.startswith(f"field_{self.offset:X}"):  # IDA 自动生成的结构体字段名
            _pure_name = self.name.removeprefix(f"field_{self.offset:X}")
        self._pure_name = _pure_name

        self._modified = False

    @classmethod
    def from_table_row(cls, row: list[str]):
        # | offset | nbytes | data_type | field_name | field_comment |
        offset, size, data_type, field_name, field_comment = row
        offset = int(offset, 16)
        size = int(size)
        data_type = data_type.strip()
        field_name = field_name.strip()
        if not field_name.startswith("fld_") and not field_name.startswith("field_"):
            field_name = f"fld_{offset:x}_{field_name}"
        field_comment = field_comment.strip()

        return cls(offset, size, data_type, field_name, field_comment)

    def to_table_row(self) -> list[str]:
        return [f"+{self.offset:X}", str(self.size), self.data_type, self._pure_name, self.comment]


def _cvt_int16_array(s: str):
    return list(map(int16, s.split(","))) if s else []


def _cvt_int_array(s: str):
    return list(map(int, s.split(","))) if s else []


@define
class Struct:
    """Markdown 文件中存储结构体表格及相关信息"""

    title: str = ""

    # 元信息
    name: str = field(default="", init=False)
    name_zh: str = field(default="", init=False)
    id: int = field(default=0xFFFFFFFF, init=False)
    size: int = field(default=0, init=False)
    comment: str = field(default="", init=False)
    array_start_addrs: list[int] = field(factory=list, init=False)
    array_end_addrs: list[int] = field(factory=list, init=False)
    array_sizes: list[int] = field(factory=list, init=False)
    array_updated: bool = field(default=False, init=False)
    last_update: str = field(default="", init=False)

    # 解析后的字段
    fields: list[StructField] = field(factory=list, init=False)  # 表格中的字段

    _content: list[str] = field(factory=list, init=False, repr=False)  # 原文件中表格以下至下一个表格标题之间的内容，用于写回文件

    _modified: bool = field(default=False, init=False, repr=False)  # 是否被修改过

    # 各元信息解析函数表
    _META_PARSE_FUNCS = {
        "struct_name": ("name", str.strip),  # 元信息名: (属性名, 处理函数)
        "struct_name_zh": ("name_zh", str.strip),
        "struct_id": ("id", int16),
        "struct_size": ("size", int16),
        "array_start_addrs": ("array_start_addrs", _cvt_int16_array),
        "array_end_addrs": ("array_end_addrs", _cvt_int16_array),
        "array_sizes": ("array_sizes", _cvt_int_array),
        "array_updated": ("array_updated", lambda x: x.lower() == "true"),
        "last_update": ("last_update", str.strip),
    }

    def parse_meta_line(self, line: str):
        if not line.startswith("- "):
            return
        line = line[2:].strip()
        for key, (attr, func) in self._META_PARSE_FUNCS.items():
            if line.startswith(key + ":"):
                try:
                    value = func(line.removeprefix(key + ":").strip())
                    setattr(self, attr, value)
                except ValueError:
                    print(f"Failed to parse {key} value: {line}, skip.")
                break

    def meta_lines(self) -> list[str]:
        lines = []
        lines.append(f"- struct_name_zh: {self.name_zh}")
        lines.append(f"- struct_name: {self.name}")
        lines.append(f"- struct_id: {self.id:08x}")
        lines.append(f"- struct_size: {self.size:#x}")
        lines.append(f"- array_start_addrs: {','.join(map(format_address, self.array_start_addrs))}")
        lines.append(f"- array_end_addrs: {','.join(map(format_address, self.array_end_addrs))}")
        lines.append(f"- array_sizes: {','.join(map(str, self.array_sizes))}")
        lines.append(f"- array_updated: {self.array_updated}")
        lines.append(f"- last_update: {self.last_update}")

        return [line.strip() + "\n" for line in lines]

    def table_string(self) -> str:
        tb = prettytable.PrettyTable()
        tb.set_style(prettytable.MARKDOWN)
        tb.align = "l"
        tb.field_names = _STRUCT_TABLE_HEADER
        for field in self.fields:
            tb.add_row(field.to_table_row())
        return tb.get_string().replace("-|", " |")  # 与 vscode markdown 插件格式化结果一致

    def is_modified(self):
        """是否被修改过"""
        return self._modified or any(f._modified for f in self.fields)


_STRUCT_INDEX_PAT = re.compile(r"\[([0-9]+)\]")


class StructMDFileParser:
    """结构体汇总.md 文件解析器"""

    _STATE_FINDING_TITLE = 0  # 正在寻找下一个表格标题
    _STATE_BEFORE_TABLE = 1  # 处理表格标题到表格上方之间的内容行
    _STATE_ON_TABLE = 2  # 处理表格内容行

    def __init__(self):
        self._structs: list[Struct] = []
        self._before_content: list[str] = []  # 第一个表格之前的内容
        self._state = self._STATE_FINDING_TITLE
        self._current_table: Struct = None
        self._specific_table_indexes: list[int] = None  # 指定要解析的表格的索引（从 1 开始）

    def _reset(self):
        self._structs.clear()
        self._before_content.clear()
        self._state = self._STATE_FINDING_TITLE
        self._current_table = None
        self._specific_table_indexes = None

    def parse(self, mk_file: str, specific_table_indexes: list[int] = None) -> list[Struct]:
        self._reset()
        self._specific_table_indexes = specific_table_indexes

        with open(mk_file, "r", encoding="utf-8") as file:
            for line in file:
                self._parse_line(line)

        return self._structs

    def _parse_line(self, line: str):
        if self._state == self._STATE_FINDING_TITLE:
            return self._state_finding_title(line)

        if self._state == self._STATE_BEFORE_TABLE:
            return self._state_before_table(line)

        if self._state == self._STATE_ON_TABLE:
            return self._state_on_table(line)

    def _create_new_struct(self, line: str):
        # 判断是否需要过滤
        table_index = 0
        if self._specific_table_indexes:
            # 表格标题形如 "## [1]xxx"，提取出表格索引
            m = _STRUCT_INDEX_PAT.search(line)
            if m:
                table_index = int(m.group(1))
        if not self._specific_table_indexes or table_index in self._specific_table_indexes:
            # 找到了一个表格标题
            title = line[3:].strip()
            self._state = self._STATE_BEFORE_TABLE
            self._current_table = Struct(title)
            self._structs.append(self._current_table)
            print(f"Found table: {title}")
            return True
        return False  # 未创建表格

    def _state_finding_title(self, line: str):
        if line.startswith("## "):
            if self._create_new_struct(line):
                return

        if not self._current_table:
            self._before_content.append(line)
        else:
            self._current_table._content.append(line)

    def _state_before_table(self, line: str):
        if self._reach_table_row(line):
            self._state = self._STATE_ON_TABLE
            return

        if line.startswith("## "):  ## 该表为空表，直接下一个表格
            if self._create_new_struct(line):
                return

        # 解析结构体元信息
        self._current_table.parse_meta_line(line)

    def _state_on_table(self, line: str):
        if not line.strip():  # 空行
            self._state = self._STATE_FINDING_TITLE
            self._current_table._content.append(line)
            return

        # 解析结构体字段
        row = list(map(str.strip, line.strip().strip("|").split("|")))
        if len(row) != len(_STRUCT_TABLE_HEADER):
            # 无效的表格行，这种情况不应该出现
            raise ValueError(f"Invalid table row: {line}")
        self._current_table.fields.append(StructField.from_table_row(row))

    def add_struct(self, struct: Struct):
        self._structs.append(struct)

    def write_file(self, file_path: str):
        """写入文件"""
        now = get_now_time()
        with open(file_path, "w", encoding="utf-8") as f:
            f.writelines(self._before_content)
            for table in self._structs:
                # 写入标题
                f.write(f"## {table.title}\n\n")
                # 写入元信息
                if table.is_modified():
                    table.last_update = now
                f.writelines(table.meta_lines())
                f.write("\n")
                # 写入表格
                f.write(table.table_string())
                f.write("\n")
                # 写入表格以下内容
                if not table._content:
                    f.write("\n\n")
                else:
                    f.writelines(table._content)

    @staticmethod
    def _reach_table_row(line: str) -> bool:
        """判断是否到达表格内容开始行"""
        return any(line.startswith(x) for x in ("| ---", "|--", "| :--", "|:--"))


def update_structs_file():
    """更新结构体文件，如结构体序号, 新建未定义结构体等"""
    parser = StructMDFileParser()
    structs = parser.parse(STRUCTS_FILE)

    # 重新编号
    for i, struct in enumerate(structs):
        # 去掉原有的序号
        items = struct.title.split("]")
        if len(items) > 1:
            struct.title = items[1].strip()
        struct.title = f"[{i+1}]{struct.title}"

    # 如果结构体 fields 为空或fields[-1]的 offset+field_size < size，添加一个 int 字段
    for struct in structs:
        if struct.size == 0:
            continue
        if not struct.fields:
            struct.fields.append(StructField(struct.size - 4, 4, "int", "", ""))
            continue
        last_field = struct.fields[-1]
        if last_field.offset + last_field.size < struct.size:
            struct.fields.append(StructField(struct.size - 4, 4, "int", "", ""))

    # 如果结构体offset=0处没有字段，添加一个 int 字段
    for struct in structs:
        for field in struct.fields:
            if field.offset == 0:
                break
        else:
            struct.fields.insert(0, StructField(0, 4, "int", "", ""))

    parser.write_file(STRUCTS_FILE)


if __name__ == "__main__":
    # 解析参数 -u
    if len(sys.argv) > 1 and sys.argv[1] == "-u":
        update_structs_file()
        sys.exit(0)

#######################################################################################################
###                                         IDA 操作相关                                             ###
#######################################################################################################


import idaapi
import idautils
import idc


def _get_data_flags(fld: StructField):
    if fld._is_ptr:
        return idaapi.FF_DWORD | idaapi.FF_1OFF | idaapi.FF_DATA
        # FF_1OFF 表示 "First Offset"（第一个偏移量）。这个标志通常用于表示一个数据成员应该被解释为一个偏移量或指针。

    dt_str = fld._pure_data_type

    if dt_str in ("byte", "char", "uchar"):
        return idaapi.byte_flag()

    if dt_str in ("word", "short", "ushort"):
        return idaapi.word_flag()

    if dt_str in ("dword", "int", "uint"):
        return idaapi.dword_flag()

    if dt_str in ("float",):
        return idaapi.float_flag()

    if dt_str in ("string",):
        return idaapi.strlit_flag()

    if is_struct_type(dt_str):
        return idaapi.stru_flag()

    return 0  # 其他类型用不到 flag


def _add_struc_member(sptr, field: StructField):
    """添加结构体或结构体数组成员"""
    member_struct_name = field._pure_data_type
    opinfo = idaapi.opinfo_t()
    opinfo.tid = idaapi.get_struc_id(member_struct_name)
    if opinfo.tid == idaapi.BADADDR:
        idaapi.warning(f"Struct '{member_struct_name}' not found")
        return False
    idaapi.add_struc_member(sptr, field.name, field.offset, idaapi.stru_flag(), opinfo, field.size)


def _add_string_member(sptr, field: StructField):
    """添加字符串成员"""
    opinfo = idaapi.opinfo_t()
    opinfo.strtype = idaapi.STRTYPE_C
    idaapi.add_struc_member(sptr, field.name, field.offset, idaapi.strlit_flag(), opinfo, field.size)


def _get_tinfo_from_base_type(base_type: str) -> idaapi.tinfo_t | None:
    """根据基础类型返回 tinfo_t 对象"""
    if base_type == "void":
        return idaapi.tinfo_t(idaapi.BT_VOID)
    if base_type in ("byte", "char", "int8"):
        return idaapi.tinfo_t(idaapi.BT_INT8)
    if base_type in ("uchar", "uint8", "unsigned char"):
        return idaapi.tinfo_t(idaapi.BT_INT8 | idaapi.BTMT_UNSIGNED)
    if base_type in ("word", "short", "int16"):
        return idaapi.tinfo_t(idaapi.BT_INT16)
    if base_type in ("ushort", "uint16", "unsigned short"):
        return idaapi.tinfo_t(idaapi.BT_INT16 | idaapi.BTMT_UNSIGNED)
    if base_type in ("dword", "int"):
        return idaapi.tinfo_t(idaapi.BT_INT32)
    if base_type in ("uint", "unsigned int"):
        return idaapi.tinfo_t(idaapi.BT_INT32 | idaapi.BTMT_UNSIGNED)
    if base_type == "float":
        return idaapi.tinfo_t(idaapi.BT_FLOAT)
    if base_type == "bool":
        return idaapi.tinfo_t(idaapi.BT_BOOL)

    return None


def _get_tinfo_from_stru_name(stru_name):
    tinfo = idaapi.tinfo_t()
    if tinfo.get_named_type(idaapi.get_idati(), stru_name):
        return tinfo
    return None


def _get_tinfo_from_data_type(data_type: str) -> idaapi.tinfo_t | None:
    """根据数据类型返回tinfo_t, 考虑基础类型和结构体类型与指针和数组嵌套定义的情况"""
    pure_data_type = get_pure_data_type(data_type)

    # 快速排查一些特例
    if pure_data_type in ("pointer", "address", "pointer32"):
        # 返回 void* 类型
        t = idaapi.tinfo_t(idaapi.BT_VOID)
        t.create_ptr(t)
        return t

    if pure_data_type == "string":
        # 返回 char[] 类型
        t = idaapi.tinfo_t(idaapi.BTF_CHAR)
        t.create_array(t)
        return t

    # 先处理基础类型和结构体类型
    t = _get_tinfo_from_base_type(pure_data_type)
    if t is None:
        t = _get_tinfo_from_stru_name(pure_data_type)
    if t is None:
        return None

    # 处理指针数组嵌套情况
    remaining = data_type[len(pure_data_type) :].strip().replace(" ", "")
    l = 0
    r = len(remaining) - 1
    cur = l
    while l <= r:
        if remaining[cur] == "*":
            t.create_ptr(t)
            l += 1
            cur = l
            # 处理一种特殊情况, 最里层的 *[, 实际应为 *(variable_name)[，所以也要跳到右边
            if l <= r and remaining[l] == "[":
                cur = r
            continue
        if remaining[cur] == "(":  # 此时应跳转到右边，从右边开始解析
            l += 1
            cur = r
            continue
        if remaining[cur] == ")":  # 此时应跳转到左边，从左边开始解析
            r -= 1
            cur = l
            continue
        if remaining[cur] == "]":  # 往左找到对应的 "["，然后解析数组大小
            r = cur - 1
            for cur in range(r, l - 1, -1):
                if remaining[cur] == "[":
                    break
            else:
                idaapi.warning(f"Invalid data type: {data_type}")
                return None
            try:
                array_size = int(remaining[cur + 1 : r + 1]) if r > cur else 0
            except ValueError:
                idaapi.warning(f"Invalid array size: {data_type} for {remaining[cur + 1 : r + 1]} is not a int.")
                return None
            t.create_array(t, array_size)
            r = cur - 1
            cur = r
            continue
        if remaining[cur] == "[":
            l = cur + 1
            for cur in range(l, r + 1):
                if remaining[cur] == "]":
                    break
            else:
                idaapi.warning(f"Invalid data type: {data_type}")
                return None
            try:
                array_size = int(remaining[l:cur]) if cur > l else 0
            except ValueError:
                idaapi.warning(f"Invalid array size: {data_type} for {remaining[l:cur]} is not a int.")
                return None
            t.create_array(t, array_size)
            l = cur + 1
            cur = l
            continue

    return t


def _find_struct_array_size(start_addr, struct_size):
    # 首先找到 start_addr 处的双字地址，这是每个结构体的标识
    func_addr = idaapi.get_wide_dword(start_addr)

    cur_addr = start_addr + struct_size
    item_cnt = 1
    while True:
        cur_func_addr = idaapi.get_wide_dword(cur_addr)
        if cur_func_addr != func_addr:
            break
        item_cnt += 1
        cur_addr += struct_size

    return item_cnt, cur_addr


def _create_struct_array(struct: Struct):
    tinfo = _get_tinfo_from_stru_name(struct.name)
    for i, array_start_addr in enumerate(struct.array_start_addrs):
        # 先找出数组的结束地址和大小
        if len(struct.array_end_addrs) > i:
            array_end_addr = struct.array_end_addrs[i]
            array_size = (array_end_addr - array_start_addr) // struct.size
            if len(struct.array_sizes) > i:
                struct.array_sizes[i] = array_size
            else:
                struct.array_sizes.append(array_size)
        elif len(struct.array_sizes) > i:
            array_size = struct.array_sizes[i]
            array_end_addr = array_start_addr + array_size * struct.size
            if len(struct.array_end_addrs) > i:
                struct.array_end_addrs[i] = array_end_addr
            else:
                struct.array_end_addrs.append(array_end_addr)
        else:  # 仅提供了起始地址，需自行查找 end_addr 和 array_size
            # 大部分结构体第一个字段是指向该类结构体函数的指针，可根据这个特征来查找数组的结束地址
            # 如果不是该特征，则无法自动查找结束地址，需要手动指定
            array_size, array_end_addr = _find_struct_array_size(array_start_addr, struct.size)
            struct.array_end_addrs.append(array_end_addr)
            struct.array_sizes.append(array_size)

            # 更新结构体相关函数所在地址名称
            func_addr_name = struct.fields[0].name.removeprefix("fld_0_")
            func_addr = idaapi.get_wide_dword(array_start_addr)
            idaapi.set_name(func_addr, func_addr_name)

        # 创建结构体数组
        idaapi.del_items(array_start_addr, idaapi.DELIT_SIMPLE, array_size * struct.size)
        make_array = not DO_NOT_MAKE_ARRAY and (array_size <= 100 or array_size * struct.size < 0x1000)
        if make_array:  # 小数组
            idaapi.create_struct(array_start_addr, struct.size, struct.id)
            if not idc.make_array(array_start_addr, array_size):
                idaapi.warning(f"Failed to create array at {array_start_addr:x}.\n")
                continue
            ap = idaapi.array_parameters_t()
            ap.flags = idaapi.AP_INDEX | idaapi.AP_IDXDEC | idaapi.AP_ARRAY
            idaapi.set_array_parameters(array_start_addr, ap)
        else:  # 大数组
            cnt = 0
            for addr in range(array_start_addr, array_end_addr, struct.size):
                idaapi.create_struct(addr, struct.size, struct.id)
                if cnt > 0:
                    idaapi.set_name(addr, f"{struct.name}_{addr:x}")
                    idaapi.set_tinfo(addr, tinfo)
                    idaapi.set_cmt(addr, f"{struct.name}_ARRAY[{cnt}]", 1)
                cnt += 1

        # 结构体数组名和注释
        array_name = f"{struct.name}_ARRAY"
        if i > 0:
            array_name += f"_{i}"
        idaapi.set_name(array_start_addr, array_name)
        array_comment = f"{array_name}[end={format_address(array_end_addr)},size={array_size},struct_size={struct.size:#x}]"
        idaapi.set_cmt(array_start_addr, array_comment, 1)

        idaapi.msg(
            f"Struct array {array_name} created, size: {array_size}, struct size: {struct.size}, start at {array_start_addr:x}, end at {array_end_addr:x}\n"
        )


def _traverse_linked_list(struct: Struct):
    node_name = LINKED_LIST_STRUCT_NAME.get(struct.name, None)
    if node_name is None:
        return
    node_sid = idaapi.get_struc_id(node_name)
    if node_sid == idaapi.BADADDR:
        return
    node_size = idaapi.get_struc_size(node_sid)
    node_tinfo = _get_tinfo_from_stru_name(node_name)
    for list_addr in struct.array_start_addrs:
        visited = set()
        # 一般链表offset=0x4处存放下一个节点的地址
        start_address = idaapi.get_wide_dword(list_addr + 4)
        current = start_address
        while current != 0 and current not in visited:
            idaapi.create_struct(current, node_size, node_sid)
            # 设置当前的 tinfo 为该 node 结构体
            idaapi.set_tinfo(current, node_tinfo)
            # 命名为 node_name+current_address
            idaapi.set_name(current, f"{node_name}_{current:x}")

            idaapi.msg(f"Current node: {current:x}\n")
            visited.add(current)

            # Get the next pointer
            next_ptr = idaapi.get_wide_dword(current)  # offset
            if next_ptr == 0 or next_ptr == idaapi.BADADDR:
                idaapi.msg("Reached end of list (null pointer)\n")
                break

            current = next_ptr

        if current in visited and current != start_address:
            idaapi.msg(f"Cycle detected at {current:x}\n")
        elif current == start_address:
            idaapi.msg("Traversal complete, returned to start node\n")

        idaapi.msg(f"Total {node_name} nodes: {len(visited)}\n")


def _import_struct(struct: Struct) -> bool:
    # 先判断结构体是否已经存在，如果存在则对齐进行更新，否则创建新的结构体
    is_update = False

    sid = struct.id
    if sid == idaapi.BADADDR:  # 若未指定 id，则根据名称查找
        sid = idaapi.get_struc_id(struct.name)
        struct.id = sid
    else:  # 若指定了 id，则根据 id 查找
        struct_name = idaapi.get_struc_name(sid)
        if struct_name != struct.name:
            idaapi.set_struc_name(sid, struct.name)
            idaapi.msg(f"Renamed struct {struct_name} to {struct.name}\n")
        sid = idaapi.get_struc_id(struct.name)

    if sid == idaapi.BADADDR:  # 不存在则创建
        sid = idaapi.add_struc(idaapi.BADADDR, struct.name)
        idaapi.msg(f"Added struct {struct.name}\n")
        struct.id = sid
    else:
        is_update = True
        idaapi.msg(f"Updating struct {struct.name}\n")

    sptr = idaapi.get_struc(sid)
    idaapi.set_struc_cmt(sid, struct.comment, True)

    # 结构体字段
    if not is_update:
        # 创建新结构体，则扩充结构体大小
        idaapi.expand_struc(sptr, 0, struct.size)

    for field in struct.fields:
        if is_update:  # 更新结构体时，先删除原有成员
            idaapi.del_struc_members(sptr, field.offset, field.offset + field.size)
        # 添加成员
        data_flag = _get_data_flags(field)
        if is_struct_type(field._pure_data_type):  # 结构体
            if field._is_ptr:  # 结构体指针
                idaapi.add_struc_member(sptr, field.name, field.offset, data_flag, None, field.size)
            else:  # 结构体或结构体数组
                _add_struc_member(sptr, field)
        elif field.data_type == "string":  # 字符串
            _add_string_member(sptr, field)
        else:  # 其他类型（基础类型，指针）
            idaapi.add_struc_member(sptr, field.name, field.offset, data_flag, None, field.size)

        mptr = idaapi.get_member(sptr, field.offset)
        if mptr == idaapi.BADADDR:
            idaapi.warning(f"Failed to add member '{field.name}' to struct '{struct.name}'")
            continue

        # set tinfo
        tinfo = _get_tinfo_from_data_type(field.data_type)
        if tinfo:
            idaapi.set_member_tinfo(sptr, mptr, 0, tinfo, 0)
        # set comment
        idaapi.set_member_cmt(mptr, field.comment, 1)

    struct_name = idaapi.get_struc_name(sid)
    struct_size = idaapi.get_struc_size(sptr)

    # 校验结构体大小是否一致
    if struct.size == struct_size:
        idaapi.msg(f"Struct {struct_name} size: {struct_size:x}\n")
    else:
        idaapi.warning(f"Struct {struct_name} size mismatch: {struct.size:x} vs {struct_size:x}\n")
        return False

    # IDA 视图中创建结构体数组
    if FORCE_UPDATE_STRUCT_ARRAYS or (not struct.array_updated and len(struct.array_start_addrs) > 0):
        if struct.name in LINKED_LIST_STRUCT_NAME:
            _traverse_linked_list(struct)
        else:
            _create_struct_array(struct)
        struct.array_updated = True

    return True


def import_structs(specific_table_indexes: list[int] = None):
    parser = StructMDFileParser()
    structs = parser.parse(STRUCTS_FILE, specific_table_indexes)
    idaapi.msg(f"Parsed structs: {len(structs)}\n")

    for i, struct in enumerate(structs):
        idaapi.msg(f"Importing {i+1}/{len(structs)}: {struct.name_zh}({struct.name}) ...\n")
        if _import_struct(struct):
            idaapi.msg("Imported.\n")
        else:
            idaapi.msg("Failed to import.\n")

    parser.write_file(STRUCTS_FILE)

    idaapi.msg("All structs imported.\n")
    idaapi.msg("-" * 80 + "\n")


def import_selected_structs():
    s = idaapi.ask_str("", 311, "Input selected struct indexes:")
    selected = list(map(int, s.split(","))) if s else None
    import_structs(selected)


def _replace_common_data_type(data_type: str) -> str:
    return data_type.replace("__int32", "int").replace("__int16", "short").replace("__int8", "byte")


def _export_structs(sid: int, struct: Struct):
    sptr = idaapi.get_struc(sid)
    struct.size = idaapi.get_struc_size(sptr)
    struct.comment = idaapi.get_struc_cmt(sid, True) or ""

    # 字段
    struct.fields.clear()
    for offset, field_name, field_size in idautils.StructMembers(sid):
        mptr = idaapi.get_member(sptr, offset)
        mid = idaapi.get_member_id(sptr, offset)
        comment = idaapi.get_member_cmt(mid, 1) or ""
        tinfo = idaapi.tinfo_t()
        data_type = ""
        if idaapi.get_member_tinfo(tinfo, mptr):
            data_type = _replace_common_data_type(tinfo.dstr())

        field = StructField(offset, field_size, data_type, field_name, comment)
        struct.fields.append(field)


def export_structs():
    idaapi.msg("-" * 80 + "\n")
    idaapi.msg("Exporting structs ...\n")

    # 先解析出已有的结构体
    parser = StructMDFileParser()
    structs = parser.parse(STRUCTS_FILE)
    sid_to_index: dict[int, int] = {}
    for i, struct in enumerate(structs):
        sid_to_index[struct.id] = i

    # 查找所有以 struct_ 开头的结构体（假设这些是我们要导出的结构体）
    for i, sid, name in idautils.Structs():
        if not name.startswith("struct_"):  # 只导出以 struct_ 开头的结构体
            continue
        if sid in sid_to_index:
            struct = structs[sid_to_index[sid]]
            old_table_str = struct.table_string()
            struct.name = name
            _export_structs(sid, struct)
            new_table_str = struct.table_string()
            struct._modified = old_table_str != new_table_str
        else:
            tb_index = len(structs) + 1
            struct = Struct(f"[{tb_index}]{name}")
            struct.id = sid
            struct.name = name
            _export_structs(sid, struct)
            struct._modified = True
            parser.add_struct(struct)

    # 写回文件
    parser.write_file(STRUCTS_FILE)

    idaapi.msg("Exported.\n")
    idaapi.msg("-" * 80 + "\n")


def action():
    # 交互式选择导入或导出
    button = idaapi.ask_buttons("Import", "Export", "Cancel", 1, "Import or export structs")
    if button == 1:
        import_structs()
    elif button == 0:
        export_structs()
    else:
        idaapi.msg("Canceled.\n")


#######################################################################################################
###                                     IDA Plugin 接口相关                                           ###
#######################################################################################################


class San11StruPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC
    comment = "Import or export structs (@san11pk)."
    help = "Shift-S to import or Alt-Shift-S to export san11pk structs."
    wanted_name = "San11StruPlugin"
    wanted_hotkey = ""

    ACTION_IMPORT = "san11:import_structs"
    ACTION_PART_IMPORT = "san11:import_part_structs"
    ACTION_EXPORT = "san11:export_structs"

    def init(self):
        # 注册 import action
        import_action_desc = idaapi.action_desc_t(
            self.ACTION_IMPORT,
            "Import structs",
            IDACtxEntry(import_structs),
            "Alt-Shift-S",
            "Import structs (@san11pk)",
            0,
        )
        assert idaapi.register_action(import_action_desc), "Failed to register action: import"
        # 注册 import part action
        import_part_action_desc = idaapi.action_desc_t(
            self.ACTION_PART_IMPORT,
            "Import part structs",
            IDACtxEntry(import_selected_structs),
            "Shift-S",
            "Import part structs (@san11pk)",
            0,
        )
        assert idaapi.register_action(import_part_action_desc), "Failed to register action: import_part"
        # 注册 export action
        export_action_desc = idaapi.action_desc_t(
            self.ACTION_EXPORT,
            "Export structs",
            IDACtxEntry(export_structs),
            "Shift-W",
            "Export structs (@san11pk)",
            0,
        )
        assert idaapi.register_action(export_action_desc), "Failed to register action: export"

        idaapi.msg("San11StruPlugin initialized.\n")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        action()

    def term(self):
        idaapi.unregister_action(self.ACTION_IMPORT)
        idaapi.unregister_action(self.ACTION_PART_IMPORT)
        idaapi.unregister_action(self.ACTION_EXPORT)
        idaapi.msg("San11StruPlugin terminated.\n")


class IDACtxEntry(idaapi.action_handler_t):
    def __init__(self, action_function):
        idaapi.action_handler_t.__init__(self)
        self.action_function = action_function

    def activate(self, ctx):
        self.action_function()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


def PLUGIN_ENTRY():
    return San11StruPlugin()


if __name__ == "__main__":
    action()
