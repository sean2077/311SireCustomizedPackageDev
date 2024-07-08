#!python
# Description: A simple tool to convert ASCII to Big5 and vice versa.
import argparse

try:
    import opencc
except ImportError:
    print("Error: Please install the opencc package.")
    print("You can install it using the following command:")
    print("pip install opencc-python-reimplemented")
    exit(1)


def ascii_to_big5(ascii_string):
    return ascii_string.encode("big5", errors="ignore")


def big5_to_ascii(big5_bytes):
    return big5_bytes.decode("big5", errors="ignore")


def bytes_to_hex_string(data):
    return " ".join([format(byte, "02X") for byte in data])


def simplified_to_traditional_string(simplified_string):
    converter = opencc.OpenCC("s2t")  # 's2t' 表示简体到繁体
    traditional_string = converter.convert(simplified_string)
    return traditional_string


def traditional_to_simplified_string(traditional_string):
    converter = opencc.OpenCC("t2s")  # 't2s' 表示繁体到简体
    simplified_string = converter.convert(traditional_string)
    return simplified_string


# 格式化 bigs 输入
def format_big5_input(big5_input):
    # 支持格式：
    # 0BCh, 0D0h, 0B7h, 0C7h, 0B8h, 0CBh, 0B3h, 0C6h, 0AAh
    # BC D0
    # BCD0

    # 如果以逗号分隔
    if "," in big5_input:
        items = big5_input.split(",")
    # 如果以空格分隔
    elif " " in big5_input:
        items = big5_input.split(" ")
    # 如果没有分隔符，直接返回
    else:
        return bytes.fromhex(big5_input)

    # 去掉 h 后缀
    items = [item.replace("h", "") for item in items]

    # 校验 16 进制数
    items = [int(item, 16) for item in items]

    return bytes(items)


def main():
    parser = argparse.ArgumentParser(description="Convert ASCII to Big5 and vice versa")
    parser.add_argument("-a", "--ascii_to_big5", metavar="STRING", help="Convert ASCII to Big5")
    parser.add_argument("-b", "--big5_to_ascii", metavar="BYTES", help="Convert Big5 to ASCII")

    args = parser.parse_args()

    if args.ascii_to_big5:
        # 先将简体转换为繁体，再转换为big5编码
        translated_string = simplified_to_traditional_string(args.ascii_to_big5)
        big5_bytes = ascii_to_big5(translated_string)
        print("Big5 编码:", bytes_to_hex_string(big5_bytes))
    elif args.big5_to_ascii:
        big5_bytes = format_big5_input(args.big5_to_ascii)
        ascii_string_back = big5_to_ascii(big5_bytes)
        print("ASCII 解码:", ascii_string_back)
    else:
        print("Error: Please specify either --ascii_to_big5/-a or --big5_to_ascii/-b.")


if __name__ == "__main__":
    main()
