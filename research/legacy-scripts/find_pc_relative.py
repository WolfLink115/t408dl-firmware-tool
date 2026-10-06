from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_ARM
from capstone.arm import ARM_OP_MEM, ARM_REG_PC

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
    strings_of_interest = [
        b'[USBDL] Waiting for start cmd',
        b'[USBDL] Waiting for host\'s response',
        b'SUSBDL',
        b'READ16',
        b'WRITE16'
    ]
    for mode_name, mode in [('Thumb', CS_MODE_THUMB), ('ARM', CS_MODE_ARM)]:
        md = Cs(CS_ARCH_ARM, mode)
        md.detail = True
        for i in md.disasm(data, 0x0):
            # Check all operands for memory operands with PC base
            for op in i.operands:
                if op.type == ARM_OP_MEM:
                    if op.mem.base == ARM_REG_PC:
                        if mode == CS_MODE_THUMB:
                            base = (i.address & 0xFFFFFFFE) + 4
                        else:
                            base = (i.address & 0xFFFFFFFC) + 8
                        addr = base + op.mem.disp
                        if addr < len(data):
                            # Extract a string from addr
                            s = extract_string(data, addr)
                            # Check if it matches any of our strings of interest
                            for target in strings_of_interest:
                                if target in s:
                                    print(f'{i.address:08x} ({mode_name}): {i.mnemonic} {i.op_str} -> points to string at 0x{addr:x}: {s}')
                                    return
    print("No PC-relative load to strings of interest found")

if __name__ == '__main__':
    main()
