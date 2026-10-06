from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_ARM
from capstone.arm import ARM_OP_IMM

def main():
    with open('/home/wolflink115/t408dl-recovery/t408dl-live-lowmem.bin', 'rb') as f:
        data = f.read()
    target_addrs = [0x000042b0, 0x000042ec]
    print(f"Searching for moves of addresses 0x{target_addrs[0]:x} and 0x{target_addrs[1]:x} in code around 0x0000E046")
    for mode_name, mode in [('Thumb', CS_MODE_THUMB), ('ARM', CS_MODE_ARM)]:
        md = Cs(CS_ARCH_ARM, mode)
        md.detail = True
        for i in md.disasm(data[0x0000e046:0x0000e200], 0x0000e046):
            for op in i.operands:
                if op.type == ARM_OP_IMM:
                    imm = op.imm
                    for addr in target_addrs:
                        if imm == (addr & 0xFFFF):
                            print(f'{i.address+0x0000e046:08x} ({mode_name}): {i.mnemonic} {i.op_str} -> moves low part 0x{imm:x} of 0x{addr:x}')
    print("Done")

if __name__ == '__main__':
    main()
