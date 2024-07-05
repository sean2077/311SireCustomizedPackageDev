import os

import idaapi


def save_memory_range(start_addr, end_addr, output_file):
    with open(output_file, "wb") as f:
        current_addr = start_addr
        while current_addr <= end_addr:
            # Read 0x1000 bytes at a time
            chunk_size = min(0x1000, end_addr - current_addr + 1)
            data = idaapi.get_bytes(current_addr, chunk_size)
            if data:
                f.write(data)
            current_addr += chunk_size


# Define the memory range you want to save
start_address = 0x00400000
end_address = 0x09C8256C

# Specify the output file path
output_filename = "san11pk_dump.exe"

# 存到桌面
output_filename = os.path.join(os.path.expanduser("~"), "Desktop", output_filename)
print(f"Saving memory range from {hex(start_address)} to {hex(end_address)} to {output_filename}")


# Save the memory range to the specified file
save_memory_range(start_address, end_address, output_filename)


print(f"Memory range from {hex(start_address)} to {hex(end_address)} saved to {output_filename}")
