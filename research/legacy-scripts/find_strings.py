import sys
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_ARM
from capstone.arm import ARM_INS_LDR, ARM_OP_MEM, ARM_REG_PC

def is_printable(s):
    return all((32 <= b <= 126) or b in (9, 10, 13) for b in s)

def find_strings(data, start, min_len=4):
    strings = []
    i = start
    while i < len(data):
        if is_printable([data[i]]):
            j = i
            while j < len(data) and is_printable([data[j]]) and data[j] != 0:
                j += 1
            if j - i >= min_len:
                strings.append((i, data[i:j]))
                i = j
            else:
                i += 1
        else:
            i += 1
    return strings

def scan_mode(data, mode, name):
    md = Cs(CS_ARCH_ARM, mode)
    md.detail = True
    strings_by_addr = {}
    # Precompute strings for quick lookup? We'll do on demand.
    for i in range(0, len(data), 4096):
        block = data[i:i+4096]
        strings = find_strings(block, 0)
        for offset, s in strings:
            strings_by_addr[i+offset] = s
    for i in md.disasm(data, 0x0):
        if i.id == ARM_INS_LDR:
            for op in i.operands:
                if op.type == ARM_OP_MEM:
                    if op.mem.base == ARM_REG_PC:
                        if mode == CS_MODE_THUMB:
                            base = (i.address & 0xFFFFFFFE) + 4
                        else: # ARM
                            base = (i.address & 0xFFFFFFFC) + 8
                        addr = base + op.mem.disp
                        if addr < len(data):
                            # Check if addr points to a string
                            if addr in strings_by_addr:
                                s = strings_by_addr[addr]
                                # Check for keywords
                                keywords = [b'USBDL', b'susbdl', b'READ16', b'WRITE16', b'S-USBDL']
                                if any(k in s for k in keywords):
                                    print(f'{i.address:08x} ({name}): {i.mnemonic} {i.op_str} -> points to string at 0x{addr:x}: {s}')
                            # Also, we can print if the string is long enough
                            elif addr+100 < len(data):
                                # Try to extract a string
                                j = addr
                                while j < len(data) and is_printable([data[j]]) and data[j] != 0:
                                    j += 1
                                if j - addr >= 4:
                                    s = data[addr:j]
                                    keywords = [b'USBDL', b'susbdl', b'READ16', b'WRITE16', b'S-USBDL']
                                    if any(k in s for k in keywords):
                                        print(f'{i.address:08x} ({name}): {i.mnemonic} {i.op_str} -> points to string at 0x{addr:x}: {s}')

def main():
    with open('/home/wolflink115/t408dl-recovery/t408dl-live-lowmem.bin', 'rb') as f:
        data = f.read()
    print('Scanning Thumb mode...')
    scan_mode(data, CS_MODE_THUMB, 'Thumb')
    print('Scanning ARM mode...')
    scan_mode(data, CS_MODE_ARM, 'ARM')

if __name__ == '__main__':
    main()
