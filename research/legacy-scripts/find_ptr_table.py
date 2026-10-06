import struct

def is_thumb_instruction(data, addr):
    # Very rough check: if the byte at addr is not 0x00 or 0xFF, and the half-word is not 0x0000 or 0xFFFF
    if addr+1 >= len(data):
        return False
    b1 = data[addr]
    b2 = data[addr+1]
    # Thumb instructions are either 2 or 4 bytes, but we just check that it's not obvious data
    # We'll just return True for now, and we can refine
    return True

def main():
    with open('/home/wolflink115/t408dl-recovery/t408dl-live-lowmem.bin', 'rb') as f:
        data = f.read()
    # Look for the string "[USBDL] Waiting for start cmd"
    target_string = b"[USBDL] Waiting for start cmd"
    string_addr = data.find(target_string)
    if string_addr == -1:
        print("String not found")
        return
    print(f"Found string at 0x{string_addr:x}")
    # Look around this address for an array of pointers
    # We'll look 256 bytes before and after
    start = max(0, string_addr - 256)
    end = min(len(data), string_addr + 256)
    ptr_size = 4  # 32-bit pointers
    # We'll look for sequences of ptr_size bytes that point to executable code
    for i in range(start, end - ptr_size + 1, ptr_size):
        # Read the pointer as little-endian
        ptr = struct.unpack('<I', data[i:i+ptr_size])[0]
        # Check if ptr points to within the binary
        if ptr < len(data):
            # Check if the memory at ptr looks like code (not all zeros or 0xFF)
            if ptr+4 < len(data):
                # Check if the first 4 bytes at ptr are not all 0x00 or 0xFF
                b = data[ptr:ptr+4]
                if b != b'\x00\x00\x00\x00' and b != b'\xff\xff\xff\xff':
                    # Also, we can check if the instruction at ptr is a valid Thumb instruction (rough)
                    if is_thumb_instruction(data, ptr):
                        print(f'Found potential pointer at 0x{i:x}: 0x{ptr:x} -> points to code at 0x{ptr:x}')
    print("Done")

if __name__ == '__main__':
    main()
