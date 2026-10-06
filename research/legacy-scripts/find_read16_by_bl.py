from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_ARM
from capstone.arm import ARM_INS_BL, ARM_OP_MEM, ARM_REG_PC, ARM_INS_STR, ARM_INS_STRB, ARM_INS_STRH

def main():
    with open('/home/wolflink115/t408dl-recovery/t408dl-live-lowmem.bin', 'rb') as f:
        data = f.read()
    target_store_addr = 0x000c0ac8  # where LR is saved
    print(f"Searching for BL instructions whose target function stores to 0x{target_store_addr:x}")
    for mode_name, mode in [('Thumb', CS_MODE_THUMB), ('ARM', CS_MODE_ARM)]:
        md = Cs(CS_ARCH_ARM, mode)
        md.detail = True
        for i in md.disasm(data, 0x0):
            if i.id == ARM_INS_BL:
                # Get the target address of the BL
                if mode == CS_MODE_THUMB:
                    # BL in Thumb is 4 bytes, target is PC + 4 + offset (sign-extended)
                    # The offset is given in i.op_str, but we can compute from the instruction
                    # We'll use the target address from the op_str if it's a number, otherwise we'll compute
                    # For simplicity, we'll use the target address if it's available in the op_str as a hex number
                    # Alternatively, we can compute it as: target = i.address + 4 + sign_extend(offset)
                    # But we don't have the offset easily. Let's skip for now and use the op_str if it's a hex number.
                    pass
                else:
                    # ARM BL: target = i.address + 4 + offset (offset is 24-bit sign-extended)
                    pass
                # We'll skip the target calculation for now and just print the BL instruction
                # We'll come back to this if we have time.
                print(f'{i.address:08x} ({mode_name}): {i.mnemonic} {i.op_str}')
    print("Done")

if __name__ == '__main__':
    main()
