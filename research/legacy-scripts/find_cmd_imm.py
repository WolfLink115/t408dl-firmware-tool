from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_ARM
from capstone.arm import ARM_OP_IMM

def main():
    with open('/home/wolflink115/t408dl-recovery/t408dl-live-lowmem.bin', 'rb') as f:
        data = f.read()
    print("Searching for immediate values 0xD0 and 0xD3 in instructions")
    for mode_name, mode in [('Thumb', CS_MODE_THUMB), ('ARM', CS_MODE_ARM)]:
        md = Cs(CS_ARCH_ARM, mode)
        md.detail = True
        for i in md.disasm(data, 0x0):
            for op in i.operands:
                if op.type == ARM_OP_IMM:
                    if op.imm == 0xD0:
                        print(f'{i.address:08x} ({mode_name}): {i.mnemonic} {i.op_str} -> imm 0xD0')
                    if op.imm == 0xD3:
                        print(f'{i.address:08x} ({mode_name}): {i.mnemonic} {i.op_str} -> imm 0xD3')
    print("Done")

if __name__ == '__main__':
    main()
