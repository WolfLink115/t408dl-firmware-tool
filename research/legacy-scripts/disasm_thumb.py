import sys
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

def disarm_thumb(data, base_addr=0):
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = True
    for i in md.disasm(data, base_addr):
        print(f"{i.address:08x}: {i.mnemonic:<8} {i.op_str}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <file> <offset> [length]")
        sys.exit(1)
    filename = sys.argv[1]
    offset = int(sys.argv[2], 0)
    length = int(sys.argv[3], 0) if len(sys.argv) > 3 else 256
    with open(filename, "rb") as f:
        f.seek(offset)
        data = f.read(length)
    disarm_thumb(data, offset)
