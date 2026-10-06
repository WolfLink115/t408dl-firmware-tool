from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_ARM
from capstone.arm import ARM_INS_LDR, ARM_OP_MEM, ARM_REG_PC
import struct

def is_pointer_table(data, start, length=16):
    # Check if the data at start looks like an array of pointers to code or strings
    # We'll check if every 4-byte word is a pointer to within the binary and points to non-zero data
    ptr_size = 4
    num_ptrs = length // ptr_size
    for i in range(num_ptrs):
        offset = start + i * ptr_size
        if offset + ptr_size > len(data):
            return False
        ptr = struct.unpack('<I', data[offset:offset+ptr_size])[0]
        if ptr >= len(data):
            return False
        # Check that the pointed-to data is not all zeros or 0xFF
        if ptr+4 < len(data):
            b = data[ptr:ptr+4]
            if b == b'\x00\x00\x00\x00' or b == b'\xff\xff\xff\xff':
                return False
        else:
            return False
    return True

def main():
    with open('/home/wolflink115/t408dl-recovery/t408dl-live-lowmem.bin', 'rb') as f:
        data = f.read()
    print("Searching for LDR from PC that loads a pointer table")
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
                            if addr < len(data):
                                # Check if the data at addr looks like a pointer table
                                if is_pointer_table(data, addr, 32):  # check 32 bytes = 8 pointers
                                    print(f'{i.address:08x} ({mode_name}): {i.mnemonic} {i.op_str} -> loads pointer table at 0x{addr:x}')
    print("Done")

if __name__ == '__main__':
    main()
