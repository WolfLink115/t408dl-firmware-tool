from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_ARM
from capstone.arm import ARM_INS_LDR, ARM_OP_MEM, ARM_REG_PC

def is_printable(s):
    return all((32 <= b <= 126) or b in (9, 10, 13) for b in s)

def extract_string(data, start):
    end = start
    while end < len(data) and is_printable([data[end]]) and data[end] != 0:
        end += 1
    return data[start:end]

def main():
    with open('/home/wolflink115/t408dl-recovery/t408dl-live-lowmem.bin', 'rb') as f:
        data = f.read()
    target_string = b"[USBDL] Waiting for start cmd"
    # Find the string in the data
    target_addr = data.find(target_string)
    if target_addr == -1:
        print("String not found")
        return
    print(f"Found string at 0x{target_addr:x}")
    # Now scan for LDR instructions that load from PC and see if they point to this address
    for mode_name, mode in [('Thumb', CS_MODE_THUMB), ('ARM', CS_MODE_ARM)]:
        md = Cs(CS_ARCH_ARM, mode)
        md.detail = True
        for i in md.disasm(data, 0x0):
            if i.id == ARM_INS_LDR:
                for op in i.operands:
                    if op.type == ARM_OP_MEM:
                        if op.mem.base == ARM_REG_PC:
                            if mode == CS_MODE_THUMB:
                                base = (i.address & 0xFFFFFFFE) + 4
                            else:
                                base = (i.address & 0xFFFFFFFC) + 8
                            addr = base + op.mem.disp
                            if addr == target_addr:
                                print(f'Found LDR at 0x{i.address:08x} ({mode_name}): {i.mnemonic} {i.op_str} -> points to string at 0x{addr:x}')
                                return
    print("No LDR pointing to the string found")

if __name__ == '__main__':
    main()
