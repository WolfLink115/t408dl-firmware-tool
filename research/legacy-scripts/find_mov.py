from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_ARM
from capstone.arm import ARM_INS_MOV, ARM_INS_MOVS, ARM_OP_REG, ARM_OP_IMM

def main():
    with open('/home/wolflink115/t408dl-recovery/t408dl-live-lowmem.bin', 'rb') as f:
        data = f.read()
    target_addr = 0x000042bc
    print(f"Searching for moves of address 0x{target_addr:x}")
    for mode_name, mode in [('Thumb', CS_MODE_THUMB), ('ARM', CS_MODE_ARM)]:
        md = Cs(CS_ARCH_ARM, mode)
        md.detail = True
        for i in md.disasm(data, 0x0):
            if i.id in (ARM_INS_MOV, ARM_INS_MOVS):
                for op in i.operands:
                    if op.type == ARM_OP_IMM:
                        if op.imm == (target_addr & 0xFFFF):
                            print(f'{i.address:08x} ({mode_name}): {i.mnemonic} {i.op_str} -> moves low part 0x{op.imm:x}')
                        if op.imm == (target_addr >> 16):
                            print(f'{i.address:08x} ({mode_name}): {i.mnemonic} {i.op_str} -> moves high part 0x{op.imm:x}')
    print("Done")

if __name__ == '__main__':
    main()
