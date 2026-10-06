from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_ARM
from capstone.arm import ARM_INS_PUSH, ARM_INS_POP, ARM_INS_STM, ARM_INS_LDM

def main():
    with open('/home/wolflink115/t408dl-recovery/t408dl-live-lowmem.bin', 'rb') as f:
        data = f.read()
    # Look for function prologues in Thumb mode
    print("Looking for function prologues in Thumb mode around 0x202b17")
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = True
    for i in md.disasm(data[0x202a00:0x202c00], 0x202a00):
        # Look for common prologue instructions
        if i.id in (ARM_INS_PUSH, ARM_INS_STM):
            print(f'{i.address+0x202a00:08x}: {i.mnemonic} {i.op_str}')
        # Also look for pop {r4, lr} or ldmfd sp!, {r4-r6, pc} as epilogue
        if i.id in (ARM_INS_POP, ARM_INS_LDM):
            print(f'{i.address+0x202a00:08x}: {i.mnemonic} {i.op_str}')
    print("Done")

if __name__ == '__main__':
    main()
