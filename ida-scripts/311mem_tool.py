"""
san11pk内存地址记录工具，支持：
- 内存地址汇总.md 中的记录导入到 IDA 中
- IDA 中的内存地址记录导出到 内存地址汇总.md
"""

import os
import re
from collections import defaultdict
from datetime import datetime

import idaapi
import idautils
import idc
from attrs import define, field
from prettytable import MARKDOWN, PrettyTable

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))

MEM_RECORDS_FILE = os.path.join(os.path.dirname(SCRIPT_DIR), "material", "内存地址汇总.md")

# 是否格式化 markdown 输出
FORMAT_MARKDOWN = False
# 是否去掉注释中的换行符
REMOVE_NEWLINE_IN_COMMENT = True

##########################################################################
###                               Utils                                ###
##########################################################################


def get_now_time() -> str:
    """获取当前时间，形如 2020-06-06 14:00:00"""
    now = datetime.now()
    return now.strftime("%Y-%m-%d %H:%M:%S")


def format_address(addr: int) -> str:
    """格式化地址"""
    return f"{addr:08x}"


def get_data_flags_size(dt_str: str) -> tuple[int, int]:
    if dt_str in ("byte",):
        return idaapi.byte_flag(), 1

    if dt_str in ("word", "short"):
        return idaapi.word_flag(), 2

    if dt_str in ("dword", "int"):
        return idaapi.dword_flag(), 4

    if dt_str in ("float",):
        return idaapi.float_flag(), 4

    if dt_str in ("pointer32", "pointer", "address"):
        return idaapi.FF_DWORD | idaapi.FF_1OFF | idaapi.FF_DATA, 4

    if dt_str in ("string",):
        return idaapi.strlit_flag(), 0

    if dt_str.startswith("struct_"):
        tid = idaapi.get_struc_id(dt_str)
        if tid == idaapi.BADADDR:
            return 0, -1
        return idaapi.stru_flag(), idaapi.get_struc_size(tid)

    return 0, -1  # 不支持类型


def is_auto_generated_name(name: str):
    auto_prefixes = ["sub_", "loc_", "j_", "def_"]
    return any(name.startswith(prefix) for prefix in auto_prefixes)


def reach_table_start(line: str) -> bool:
    """判断是否到达表格内容开始行"""
    return any(line.startswith(x) for x in ("| ---", "|--", "| :--", "|:--"))


def format_comment(comment: str) -> str:
    """注释"""
    comment = comment.strip()
    if REMOVE_NEWLINE_IN_COMMENT:
        comment = comment.replace("\\n", "").replace("\n", "")
    else:
        comment = comment.replace("\\n", "\n")
    return comment


##########################################################################
###                           内存地址记录相关                            ###
##########################################################################

RECORD_FIELDS = ("地址", "类型", "名称", "注释", "附加信息")


@define
class Record:
    address: int
    type: str
    name: str = ""
    comment: str = field(default="", converter=format_comment)
    info: dict = field(factory=dict)  # 附加信息, 形如 key1=value1,key2=value2

    @classmethod
    def from_table_row(cls, row: str):  # | 地址 | 类型 | 名称 | 注释 | 附加信息 |
        items = row.strip().strip("|").split("|")
        if len(items) != len(RECORD_FIELDS):
            raise ValueError(f"Invalid row: {row}")
        address, type_, name, comment, info = items
        address = int(address, 16)
        type_ = type_.strip()
        name = name.strip()
        comment = comment.strip()
        ret = cls(address, type_, name, comment)

        # 附加信息
        info = info.strip()
        if info:
            for item in info.split(";"):
                key, value = item.split("=")
                ret.info[key.strip()] = value.strip()

        return ret

    def check_opt(self, key: str) -> bool:
        """检查附加信息中是否存在 key, 且值为 1"""
        return key in self.info and self.info[key] == "1"

    def to_row(self) -> list[str]:
        return [
            format_address(self.address),
            self.type,
            self.name,
            self.comment.replace("\n", "\\n"),  # markdown 表格行中不支持换行
            ";".join([f"{k}={v}" for k, v in self.info.items()]),  # 附加信息
        ]


# 记录有问题的 record
_bad_records: dict[str, list[tuple[Record, str]]] = defaultdict(list)


def _add_bad_record(record: Record, reason_type: str, detail: str = ""):
    _bad_records[reason_type].append((record, detail))
    if detail:
        idaapi.msg(detail)


def _print_bad_records():
    for reason_type, records in _bad_records.items():
        idaapi.msg(f"Bad records ({reason_type}): {len(records)}\n")
        for record, detail in records:
            detail = detail.strip("\n")
            idaapi.msg(f"- {record.address:x} {record.name}: {detail}\n")


def collect_records(file_path: str = MEM_RECORDS_FILE) -> tuple[list[Record], dict[int, int]]:
    records = []
    record_addr_idx_map = {}
    name_set = set()

    with open(file_path, "r", encoding="utf-8") as f:
        reach_records = False
        for line in f:
            line = line.strip()
            if not line:
                if reach_records:  # 读取到记录后的空行，结束
                    break
                continue
            if not reach_records:
                if reach_table_start(line):
                    reach_records = True
                continue
            if reach_records:
                record = Record.from_table_row(line)
                # 名称冲突处理
                if record.name:
                    if record.name in name_set:
                        record.name += f"_{record.address:x}"
                        _add_bad_record(record, "name_conflict")
                    name_set.add(record.name)
                records.append(record)
                record_addr_idx_map[record.address] = len(records) - 1

    return records, record_addr_idx_map


def save_records(records: list[Record], dest_file: str = MEM_RECORDS_FILE):
    rows = []
    for record in records:
        rows.append(record.to_row())

    tb = PrettyTable()
    tb.set_style(MARKDOWN)
    tb.align = "l"
    tb.field_names = RECORD_FIELDS
    for row in rows:
        tb.add_row(row)

    # 先找出表格前的内容
    headers = []
    with open(dest_file, "r", encoding="utf-8") as f:
        for line in f:
            if reach_table_start(line):
                break
            if line.startswith("(最后更新时间："):
                line = f"(最后更新时间：{get_now_time()})\n"
            headers.append(line)
    headers = headers[:-1]  # 去掉表头

    with open(dest_file, "w", encoding="utf-8") as f:
        f.writelines(headers)
        if FORMAT_MARKDOWN:
            f.write(tb.get_string().replace("-|", " |"))  # 与 vscode markdown 插件格式化结果一致
        else:
            f.write((f"| {' | '.join(RECORD_FIELDS)} |\n"))
            f.write(f"| {' | '.join(['---'] * len(RECORD_FIELDS) )} |\n")
            for row in rows:
                f.write(f"| {' | '.join(row) } |\n")
        f.write("\n")


def sort_records(records: list[Record]):
    """对 records 进行排序"""
    # 默认按（类别, 地址）排序
    records.sort(key=lambda x: (x.type, x.address))


def _import_function(record: Record) -> bool:
    """导入类型为 "函数" 的记录"""
    func = idaapi.get_func(record.address)
    if not func or func.start_ea != record.address:
        return False

    idaapi.set_name(record.address, record.name)
    idaapi.set_func_cmt(record.address, record.comment, True)
    idaapi.msg(f"- Function at {record.address:x} name updated to {record.name}.\n")

    # 处理函数声明
    decl = idaapi.print_type(record.address, idaapi.PRTYPE_1LINE | idaapi.NTF_CHKSYNC)
    # 若未记录函数声明，则记录
    if "decl" not in record.info:
        if decl:
            record.info["decl"] = decl
    else:  # 否则，尝试更新函数签名
        tinfo = idaapi.tinfo_t()
        if idaapi.parse_decl(tinfo, None, record.info["decl"] + ";", idaapi.PT_SIL) is not None:
            if idaapi.apply_tinfo(record.address, tinfo, idaapi.TINFO_DEFINITE):
                idaapi.msg(f"- Function at {record.address:x} declaration updated to {record.info['decl']}.\n")
            else:
                _add_bad_record(
                    record,
                    "decl_update_failed",
                    f"Failed to update function at {record.address:x} declaration.\n",
                )
        else:
            # 无法解析函数声明，则更新函数签名为 IDA 中的签名
            _add_bad_record(
                record,
                "decl_parse_failed",
                f"Failed to parse function at {record.address:x} declaration: {record.info['decl']}, record declaration in IDA.\n",
            )
            if decl:
                record.info["decl"] = decl

    return True


def _import_parameter(record: Record) -> bool:
    """导入类型为 "参数" 的记录"""
    param_type = record.info.get("type", None)
    if not param_type:
        idaapi.msg(f"- Parameter at {record.address:x} has no type info. Skipped.\n")
        return False

    dt_flag, dt_sz = get_data_flags_size(param_type)
    if dt_sz == -1:
        _add_bad_record(record, "unsupported_data_type", f"Unsupported data type: {param_type}. Skipped.\n")
        return False

    if param_type.startswith("struct_"):
        tid = idaapi.get_struc_id(param_type)
        if not idaapi.create_struct(record.address, dt_sz, tid):
            _add_bad_record(record, "create_struct_failed", f"Failed to create struct {param_type} at {record.address:x}.\n")
            return False
    else:
        if not idaapi.create_data(record.address, dt_flag, dt_sz, idaapi.BADNODE):
            _add_bad_record(record, "create_data_failed", f"Failed to create data type {param_type} at {record.address:x}.\n")
            return False

    idaapi.set_name(record.address, record.name, idaapi.SN_NOWARN)
    idaapi.set_cmt(record.address, record.comment, True)
    idaapi.msg(f"- Parameter at {record.address:x} created, named to {record.name}.\n")

    return True


def _import_table(record: Record, records: list[Record], addr2idx: dict[int, int]) -> bool:
    """导入类型为 "数表" 的记录"""
    table_type = record.info.get("type", None)  # data_type[array_size]
    if not table_type:
        _add_bad_record(record, "no_table_type", f"Table at {record.address:x} has no type info. Skipped.\n")
        return False

    # 解析 data_type 和 array_size
    pattern = r"(\w+)\[(\d+)\]"
    m = re.match(pattern, table_type)
    if not m:
        _add_bad_record(record, "invalid_table_type", f"Invalid table type: {table_type}. Skipped.\n")
        return False
    dt_str, array_size = m.groups()
    array_size = int(array_size)
    dt_flag, dt_sz = get_data_flags_size(dt_str)
    if dt_sz == -1:
        _add_bad_record(record, "unsupported_data_type", f"Unsupported data type: {dt_str}. Skipped.\n")
        return False

    # 去掉原有定义
    idaapi.del_items(record.address, idaapi.DELIT_SIMPLE, array_size * dt_sz)

    # 首先定义 record.address 处的数据结构
    is_struct_array = dt_str.startswith("struct_")
    if is_struct_array:  # 结构体数组
        tid = idaapi.get_struc_id(dt_str)
        if not idaapi.create_struct(record.address, dt_sz, tid):
            _add_bad_record(record, "create_struct_failed", f"Failed to create struct {dt_str} at {record.address:x}.\n")
            return False
    else:
        if not idaapi.create_data(record.address, dt_flag, dt_sz, idaapi.BADNODE):
            _add_bad_record(record, "create_data_failed", f"Failed to create data type {dt_str} at {record.address:x}.\n")
            return False

    # 一些选项
    no_array = record.check_opt("no_array")  # 不作为一个整体创建数组
    no_append_cmt = record.check_opt("no_append_cmt")  # 不追加注释

    # 创建数组
    is_small_array = array_size <= 100 or array_size * dt_sz < 0x1000  # 小数组
    create_struct_array = not no_array and is_small_array
    if create_struct_array:  # 作为一个整体创建数组
        if not idc.make_array(record.address, array_size):
            _add_bad_record(record, "create_array_failed", f"Failed to create array at {record.address:x}.\n")
            return False
        # 设置数组参数
        ap = idaapi.array_parameters_t()
        ap.flags = idaapi.AP_INDEX | idaapi.AP_ARRAY
        if record.check_opt("idxhex"):
            ap.flags |= idaapi.AP_IDXDEC  # 默认十进制
        else:
            ap.flags |= idaapi.AP_IDXHEX
        ap.lineitems = 0 if is_struct_array else 1
        if record.info.get("lineitems", None):
            ap.lineitems = int(record.info["lineitems"])
        idaapi.set_array_parameters(record.address, ap)
    else:  # 逐个创建数组元素
        for i in range(1, array_size):
            addr = record.address + i * dt_sz
            if is_struct_array:
                if not idaapi.create_struct(addr, tid):
                    _add_bad_record(record, "create_struct_failed", f"Failed to create struct {dt_str} at {addr:x}.\n")
                    continue
            else:
                if not idc.create_data(addr, dt_flag, dt_sz, idaapi.BADNODE):
                    _add_bad_record(record, "create_data_failed", f"Failed to create data type {dt_str} at {addr:x}.\n")
                    continue

            # 设置数组元素注释
            if not no_append_cmt:
                if dt_str == "address":
                    idaapi.set_cmt(addr, "", True)  # 每个地址元素的 repeatable comment 不应被覆盖
                else:
                    idaapi.set_cmt(addr, f"{record.name}[{i}]", True)

                # 一些额外处理

                # 如果元素为地址，则对指向的地址附加 repeatable 注释
                if dt_str == "address":
                    dst_addr = idaapi.get_wide_dword(addr)
                    dst_func = idaapi.get_func(dst_addr)
                    if dst_func and dst_func.start_ea == dst_addr:  # 函数首地址
                        dst_comment = idaapi.get_func_cmt(dst_func, True) or ""
                        add_comment = f"[{record.name}+{4*i:x}]"
                        if not no_append_cmt and add_comment not in dst_comment:
                            dst_comment += " " + add_comment
                            idaapi.set_func_cmt(dst_addr, dst_comment, True)
                        # 更新函数记录
                        if dst_addr in addr2idx:
                            dst_record = records[addr2idx[dst_addr]]
                            dst_record.comment = dst_comment
                        else:
                            new_record = Record(dst_addr, "函数", comment=dst_comment)
                            records.append(new_record)
                            addr2idx[dst_addr] = len(records) - 1
                    else:  # 非函数
                        dst_comment = idaapi.get_cmt(dst_addr, True) or ""
                        add_comment = f"[{record.name}+{4*i:x}]"
                        if not no_append_cmt and add_comment not in dst_comment:
                            dst_comment += " " + add_comment
                            idaapi.set_cmt(dst_addr, dst_comment, True)
                        # 更新地址记录
                        if dst_addr in addr2idx:
                            dst_record = records[addr2idx[dst_addr]]
                            dst_record.comment = dst_comment
                        else:
                            new_record = Record(dst_addr, "地址", comment=dst_comment)
                            records.append(new_record)
                            addr2idx[dst_addr] = len(records) - 1

    # 补充数组信息
    array_detail = f"[end={record.address+dt_sz*array_size:x},size={array_size},item_size={dt_sz:#x}]"
    if not record.comment.endswith(array_detail):
        record.comment += " " + array_detail

    idaapi.set_name(record.address, record.name, idaapi.SN_NOWARN)
    idaapi.set_cmt(record.address, record.comment, True)
    idaapi.msg(f"- Table at {record.address:x} created, size: {array_size}, named to {record.name}.\n")

    return True


def import_records():
    """读取 records_file 中的记录，导入到 IDA 中, 并将更新的信息保存到 records_file 中"""
    records_file = MEM_RECORDS_FILE

    idaapi.msg("-" * 80 + "\n")
    idaapi.msg(f"Importing records from {records_file}...\n")

    records, addr2idx = collect_records(records_file)

    for record_index in range(len(records)):
        record = records[record_index]
        match (record.type):

            case "函数":  # 1. 如果为函数开头地址，更新函数名称和注释
                _import_function(record)
            case "参数":  # 2. 如果为参数，创建数据
                _import_parameter(record)
            case "数表":  # 3. 如果为数表，创建数组
                _import_table(record, records, addr2idx)
            case _:  # 其他情况，更新地址名称和注释
                idaapi.set_name(record.address, record.name, idaapi.SN_NOWARN)
                idaapi.set_cmt(record.address, record.comment, True)
                idaapi.msg(f"- Address at {record.address:x} name updated to {record.name}.\n")

    # 刷新 IDA 视图和 反编译视图
    window_refresh_flags = idaapi.IWID_DISASM | idaapi.IWID_PSEUDOCODE
    idaapi.request_refresh(window_refresh_flags)
    idaapi.refresh_idaview()

    # 按(类别，地址)排序
    sort_records(records)

    # 找出地址重复的记录
    addr_set = set()
    duplicate_records = []
    for record in records:
        if record.address in addr_set:
            duplicate_records.append(record)
            # records.remove(record)
        addr_set.add(record.address)
    idaapi.msg(f"Found {len(duplicate_records)} duplicate records:\n")
    for record in duplicate_records:
        idaapi.msg(f"- {record.address:x} {record.name}\n")
    print()

    # 输出有问题的记录
    _print_bad_records()
    print()

    # 保存记录
    save_records(records, records_file)

    idaapi.msg(f"Records imported from {records_file}.\n")
    idaapi.msg("Done.\n")
    idaapi.msg("-" * 80 + "\n")


def export_records():
    """读取 IDA 中已知内存地址记录的名称和注释等信息，导出到 records_file 中"""
    records_file = MEM_RECORDS_FILE

    idaapi.msg("-" * 80 + "\n")
    idaapi.msg(f"Exporting records to {records_file}...\n")

    # 读取记录
    records, addr2idx = collect_records(records_file)

    for record in records:
        match (record.type):
            case "函数":
                func = idaapi.get_func(record.address)
                if func and func.start_ea == record.address:
                    name = idaapi.get_func_name(record.address)
                    if not is_auto_generated_name(name):
                        record.name = name
                    record.comment = idaapi.get_func_cmt(record.address, True) or ""
                    # 更新函数声明
                    decl = idaapi.print_type(record.address, idaapi.PRTYPE_1LINE | idaapi.NTF_CHKSYNC)
                    if decl:
                        record.info["decl"] = decl
            case _:
                name = idaapi.get_name(record.address)
                if not is_auto_generated_name(name):
                    record.name = name
                record.comment = idaapi.get_cmt(record.address, True) or ""

    # 找出 IDA functions 中其他带注释的函数（带注释表示在 IDA 对该函数做了记录）
    for func_ea in idautils.Functions():
        if func_ea not in addr2idx:
            cmt = idaapi.get_func_cmt(func_ea, True)
            if not cmt:
                continue
            # 去掉一些特例
            if any(cmt.startswith(prefix) for prefix in ("Microsoft", "MFC", "?")):
                continue
            record = Record(func_ea, "函数", comment=cmt)
            name = idaapi.get_func_name(func_ea)
            if not is_auto_generated_name(name):
                record.name = name
            # 更新函数声明
            decl = idaapi.print_type(func_ea, idaapi.PRTYPE_1LINE | idaapi.NTF_CHKSYNC)
            if decl:
                record.info["decl"] = decl
            records.append(record)
            addr2idx[func_ea] = len(records) - 1

            idaapi.msg(f"Function at {func_ea:x} exported.\n")

    # 找出其他带注释的 Names
    for ea, name in idautils.Names():
        if ea not in addr2idx:
            cmt = idaapi.get_cmt(ea, True)
            if not cmt:
                continue
            # 忽略一些特例
            if name.startswith("a"):
                continue
            if any(name.startswith(prefix) for prefix in ("stru", "sub_", "loc_", "j_", "def_", "__", "unknown_")):
                continue
            if any(cmt.startswith(prefix) for prefix in ("Microsoft", "MFC", "?", "D3DX", "jumptable")):
                continue

            record = Record(ea, "地址", name, cmt)
            records.append(record)
            addr2idx[ea] = len(records) - 1

            idaapi.msg(f"Name {name} at {ea:x} exported.\n")

    # 按(类别，地址)排序
    sort_records(records)

    # 保存记录
    save_records(records, records_file)

    idaapi.msg(f"{len(records)} records exported to {records_file}.\n")
    idaapi.msg("Done.\n")
    idaapi.msg("-" * 80 + "\n")


def action():
    # 交互式选择导入或导出
    button = idaapi.ask_buttons("Import", "Export", "Cancel", 1, "Import or export memory records")
    if button == 1:
        import_records()
    elif button == 0:
        export_records()
    else:
        idaapi.msg("Canceled.\n")


##########################################################################
###                        IDA Plugin 接口相关                           ###
##########################################################################


class San11MemPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC
    comment = "Import or export memory records (@san11pk)."
    help = "Alt-Shift-M to import or export san11pk memory records."
    wanted_name = "San11MemPlugin"
    wanted_hotkey = "Alt-Shift-M"

    ACTION_IMPORT = "san11:import_memory"
    ACTION_EXPORT = "san11:export_memory"

    def init(self):
        # 注册 import action
        import_action_desc = idaapi.action_desc_t(
            self.ACTION_IMPORT,
            "Import memory records",
            IDACtxEntry(import_records),
            "Shift-I",
            "Import memory records (@san11pk)",
            0,
        )
        assert idaapi.register_action(import_action_desc), "Failed to register action: import"
        # 注册 export action
        export_action_desc = idaapi.action_desc_t(
            self.ACTION_EXPORT,
            "Export memory records",
            IDACtxEntry(export_records),
            "Shift-E",
            "Export memory records (@san11pk)",
            0,
        )
        assert idaapi.register_action(export_action_desc), "Failed to register action: export"

        idaapi.msg("San11MemPlugin initialized.\n")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        action()

    def term(self):
        idaapi.unregister_action(self.ACTION_IMPORT)
        idaapi.unregister_action(self.ACTION_EXPORT)
        idaapi.msg("San11MemPlugin terminated.\n")


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
    return San11MemPlugin()


if __name__ == "__main__":
    action()
