from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_ARM
import sys

def disasm(data, base_addr, mode, name):
    md = Cs(CS_ARCH_ARM, mode)
    md.detail = True
    for i in md.disasm(data[base_addr:base_addr+0x200], base_addr):
        print(f'{i.address:08x}: {i.mnemonic:<8} {i.op_str}')

def main():
    with open('/home/wolflink115/t408dl-recovery/t408dl-live-lowmem.bin', 'rb') as f:
        data = f.read()
    addr = 0x00102900
    print(f'Disassembling around 0x{addr:x} in Thumb mode:')
    disasm(data, addr, CS_MODE_THUMB, 'Thumb')
    print(f'Disassembling around 0x{addr:x} in ARM mode:')
    disasm(data, addr, CS_MODE_ARM, 'ARM')

if __name__ == '__main__':
    main()
