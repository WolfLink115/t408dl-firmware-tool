from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_ARM
from capstone.arm import ARM_OP_MEM, ARM_REG_PC, ARM_INS_LDR, ARM_INS_BX, ARM_INS_BLX

def main():
    with open('/home/wolflink115/t408dl-recovery/t408dl-live-lowmem.bin', 'rb') as f:
        data = f.read()
    # We'll look for LDR instructions that load from a register (not PC) and then a BX/BLX to that register
    # We'll do a simple pattern match: look for LDR Rd, [Rn, #imm] followed by BX Rd or BLX Rd
    # We'll do it for a large range but we'll limit to the first 2MB to avoid taking too long
    max_addr = 0x200000
    print(f"Searching for indirect branch patterns in 0x0-{max_addr:x}")
    for mode_name, mode in [('Thumb', CS_MODE_THUMB), ('ARM', CS_MODE_ARM)]:
        md = Cs(CS_ARCH_ARM, mode)
        md.detail = True
        for i in md.disasm(data[:max_addr], 0x0):
            if i.id == ARM_INS_LDR:
                for op in i.operands:
                    if op.type == ARM_OP_MEM:
                        if op.mem.base != ARM_REG_PC:  # we want register base
                            # Remember this LDR instruction: it loads a register from [Rn, #imm]
                            # We'll store it and look for a BX/BLX to the same register within a few instructions
                            pass
            # We'll also look for BX/BLX and see if the register was recently loaded from memory
    print("Done")

if __name__ == '__main__':
    main()
