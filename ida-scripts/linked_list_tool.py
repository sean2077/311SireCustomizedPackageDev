import idaapi


def traverse_linked_list(start_address: int):
    sid = idaapi.get_struc_id(node_name)
    if sid == idaapi.BADADDR:
        print("Failed to create or get structure")
        return

    visited = set()
    current = start_address

    while current != 0 and current not in visited:
        idaapi.create_struct(current, node_size, sid)
        print(f"Current node: {current:x}")
        visited.add(current)

        # Get the next pointer
        next_ptr = idaapi.get_wide_dword(current + 4)  # fld_4_next offset
        if next_ptr == 0:
            print("Reached end of list (null pointer)")
            break

        current = next_ptr

    if current in visited and current != start_address:
        print(f"Cycle detected at {current:x}")
    elif current == start_address:
        print("Traversal complete, returned to start node")

    print("Total nodes: ", len(visited))


def create_structs(start_addr, end_addr, struct_name):
    """创建从 start_addr 到 end_addr 的结构体"""
    sid = idaapi.get_struc_id(struct_name)
    if sid == idaapi.BADADDR:
        print("Failed to create or get structure")
        return

    size = idaapi.get_struc_size(sid)

    cnt = 0
    for addr in range(start_addr, end_addr, size):
        idaapi.create_struct(addr, size, sid, True)
        cnt += 1
        print(f"Created struct at {addr:x}")

    print(f"Total structs created: {cnt}")


# start_address = idaapi.ask_addr(0, "Enter the start address of the linked list")

node_name = "struc_mem_block_meta"
node_size = 0x10
start_address = 0x050908F0
traverse_linked_list(start_address)


# start_addr = 0x06EE9950
# end_addr = 0x06EEBE90
# struct_name = "struct_person_list_node"
# create_structs(start_addr, end_addr, struct_name)
