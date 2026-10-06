from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_ARM
from capstone.arm import ARM_INS_LDR, ARM_INS_STR, ARM_INS_LDRSB, ARM_INS_LDRSH, ARM_OP_MEM, ARM_REG_PC

def is_mem_access(insn):
    return insn.id in (ARM_INS_LDR, ARM_INS_STR, ARM_INS_LDRSB, ARM_INS_LDRSH)

def main():
    with open('/home/wolflink115/t408dl-recovery/t408dl-live-lowmem.bin', 'rb') as f:
        data = f.read()
    # Addresses of interest
    addr1 = 0x0010043c  # S-USBDL
    addr2 = 0x000c0ac8  # READ16 saved-LR
    print(f"Searching for memory accesses to 0x{addr1:x} and 0x{addr2:x}")
    for mode_name, mode in [('Thumb', CS_MODE_THUMB), ('ARM', CS_MODE_ARM)]:
        md = Cs(CS_ARCH_ARM, mode)
        md.detail = True
        for i in md.disasm(data, 0x0):
            if is_mem_access(i):
                for op in i.operands:
                    if op.type == ARM_OP_MEM:
                        # Calculate the memory address being accessed
                        addr = None
                        if op.mem.base == ARM_REG_PC:
                            if mode == CS_MODE_THUMB:
                                base = (i.address & 0xFFFFFFFE) + 4
                            else:
                                base = (i.address & 0xFFFFFFFC) + 8
                            addr = base + op.mem.disp
                        else:
                            # We don't handle register base without offset for simplicity
                            pass
                        if addr is not None and (addr == addr1 or addr == addr2):
                            print(f'{i.address:08x} ({mode_name}): {i.mnemonic} {i.op_str} -> accesses 0x{addr:x}')
                        # Also, look for immediate offsets that match the address
                        # For example, if the instruction is like LDR R0, [R1, #offset] and R1 holds the base
                        # We cannot resolve without register values, so skip.
    print("Done")

if __name__ == '__main__':
    main()
