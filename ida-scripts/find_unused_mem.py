import idaapi
import idautils
import idc

# 开始搜查的地址
START_ADDR = 0x008E3000

# 结束搜查的地址
END_ADDR = 0x09C1EFFF


def find_unused_segments(segment_size=0x1000):
    # 首先找出所有内容为0的地址段
    unused_blocks = []

    for seg_start in idautils.Segments():
        seg_end = idc.get_segm_end(seg_start)

        if seg_end < START_ADDR or seg_start > END_ADDR:
            print(f"Skipping segment at {seg_start:#x} - {seg_end:#x}")
            continue

        seg_start = max(seg_start, START_ADDR)
        seg_end = min(seg_end, END_ADDR)

        print(f"Checking segment at {seg_start:#x} - {seg_end:#x}")

        addr = seg_start
        while addr < seg_end:
            print(f"- Checking address {addr:#x} to {addr + segment_size:#x}")
            # 检查当前地址段是否全为 0
            for i in range(0, segment_size, 32):
                if idaapi.get_32bit(addr + i) != 0:
                    break
            else:
                unused_blocks.append((addr, addr + segment_size))

            addr += segment_size

    # 找出所有未引用的地址段
    name_eas = [ea for ea, _ in idautils.Names()]
    block_idx = 0
    name_idx = 0
    remove_block_idxs = []
    while block_idx < len(unused_blocks) and name_idx < len(name_eas):
        block_start, block_end = unused_blocks[block_idx]
        name_ea = name_eas[name_idx]

        if block_start <= name_ea < block_end:
            remove_block_idxs.append(block_idx)
            block_idx += 1
        else:
            name_idx += 1

    new_unused_blocks = []
    for idx, block in enumerate(unused_blocks):
        if idx not in remove_block_idxs:
            new_unused_blocks.append(block)

    # 合并相邻的地址段
    merged_blocks = []
    start, end = new_unused_blocks[0]
    for i, (s, e) in enumerate(new_unused_blocks[1:], 1):
        if s <= end and e > end:
            end = e
        else:
            merged_blocks.append((start, end))
            start, end = s, e

    return merged_blocks


res = find_unused_segments()

print(f"Found {len(res)} unused memory blocks:")
for start, end in res:
    print(f"Start: {start:#x}, End: {end:#x}")


# TODO 待完善
