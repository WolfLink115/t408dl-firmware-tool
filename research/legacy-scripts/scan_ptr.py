import struct
import sys

with open('ota/stock/preloader_raw.img', 'rb') as f:
    data = f.read()

base = 0x00200F10  # runtime base
size = len(data)
print(f"Image size: {size} bytes")
print(f"Runtime range: {base:#x} - {base+size:#x}")

# Look for sequences of 4-byte little-endian pointers that point to within the image range
pointers = []
for i in range(0, size-3, 4):
    val = struct.unpack_from('<I', data, i)[0]
    if base <= val < base+size:
        pointers.append((i, val))

print(f"Found {len(pointers)} potential pointers")
# Group consecutive pointers (potential tables)
tables = []
if pointers:
    start = pointers[0][0]
    prev_ptr = pointers[0][1]
    prev_idx = pointers[0][0]
    for idx, ptr in pointers[1:]:
        if idx == prev_idx + 4 and base <= ptr < base+size:
            # consecutive
            prev_ptr = ptr
            prev_idx = idx
        else:
            # end of table
            tables.append((start, prev_idx+4))
            start = idx
            prev_ptr = ptr
            prev_idx = idx
    tables.append((start, prev_idx+4))

print(f"Found {len(tables)} pointer tables:")
for start, end in tables:
    print(f"  Table at file offset {start:#x}-{end:#x} ({end-start} bytes)")
    # Show first few entries
    for i in range(start, min(start+16, end), 4):
        val = struct.unpack_from('<I', data, i)[0]
        print(f"    {i:#x}: {val:#x}")
