#!/usr/bin/env python3

import struct
import tempfile
import unittest
import zlib
from pathlib import Path

import t408dl_storage as s


def make_gpt():
    bs = 0x200
    entry_count = 8
    entry_size = 0x80
    entries = bytearray(entry_count * entry_size)

    def add(i, name, first_lba, last_lba):
        off = i * entry_size
        entries[off:off+16] = bytes.fromhex('00112233445566778899AABBCCDDEEFF')
        entries[off+16:off+32] = bytes([i + 1]) * 16
        struct.pack_into('<QQQ', entries, off + 0x20, first_lba, last_lba, 0)
        raw = name.encode('utf-16le')
        entries[off+0x38:off+0x38+len(raw)] = raw

    add(0, 'lk', 0x100, 0x10F)
    add(1, 'super', 0x200, 0x2FF)

    entries_crc = zlib.crc32(entries) & 0xFFFFFFFF
    hdr = bytearray(bs)
    hdr[:8] = b'EFI PART'
    struct.pack_into('<I', hdr, 0x08, 0x00010000)
    struct.pack_into('<I', hdr, 0x0C, 0x5C)
    struct.pack_into('<I', hdr, 0x10, 0)
    struct.pack_into('<I', hdr, 0x14, 0)
    struct.pack_into('<QQQQ', hdr, 0x18, 1, 0xFFF, 0x22, 0xFFE)
    hdr[0x38:0x48] = bytes.fromhex('00112233445566778899AABBCCDDEEFF')
    struct.pack_into('<QIII', hdr, 0x48, 2, entry_count, entry_size, entries_crc)
    tmp = bytearray(hdr[:0x5C])
    struct.pack_into('<I', tmp, 0x10, 0)
    crc = zlib.crc32(tmp) & 0xFFFFFFFF
    struct.pack_into('<I', hdr, 0x10, crc)
    return bytes(hdr), bytes(entries)


class GPTTests(unittest.TestCase):
    def test_parse_valid(self):
        hdr, entries = make_gpt()
        table = s.parse_primary_gpt(hdr, entries, user_size=0x200000)
        self.assertEqual(len(table.partitions), 2)
        self.assertEqual(table.by_name('LK').name, 'lk')
        self.assertEqual(table.by_name('super').start, 0x200 * 0x200)

    def test_bad_header_crc(self):
        hdr, entries = make_gpt()
        bad = bytearray(hdr)
        bad[0x20] ^= 1
        with self.assertRaises(s.GPTError):
            s.parse_primary_gpt(bytes(bad), entries)

    def test_bad_entries_crc(self):
        hdr, entries = make_gpt()
        bad = bytearray(entries)
        bad[0x40] ^= 1
        with self.assertRaises(s.GPTError):
            s.parse_primary_gpt(hdr, bytes(bad))

    def test_image_guard(self):
        hdr, entries = make_gpt()
        p = s.parse_primary_gpt(hdr, entries).by_name('lk')
        s.validate_full_partition_image(p, p.size)
        with self.assertRaises(RuntimeError):
            s.validate_full_partition_image(p, p.size - 0x200)


class HelperTests(unittest.TestCase):
    def test_collision_safe_path(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'boot.bin'
            p.write_bytes(b'x')
            self.assertEqual(s.collision_safe_path(p).name, 'boot.1.bin')

    def test_classification(self):
        self.assertEqual(s.classify_partition('super'), 'firmware')
        self.assertEqual(s.classify_partition('nvram'), 'private')
        self.assertEqual(s.classify_partition('cache'), 'state')

    def test_preloader_layout(self):
        boot0 = bytearray(0x400000)
        boot0[:9] = b'EMMC_BOOT'
        brlyt = 0x200
        pre = 0x800
        length = 0x4000
        struct.pack_into('<I', boot0, 0x10, brlyt)
        boot0[brlyt:brlyt+5] = b'BRLYT'
        struct.pack_into('<I', boot0, brlyt + 0x0C, pre)
        boot0[pre:pre+4] = b'MMM\x01'
        struct.pack_into('<I', boot0, pre + 0x20, length)
        marker = pre + 0x100
        boot0[marker:marker+16] = b'MTK_BLOADER_INFO'
        info = s.parse_preloader_from_boot0(bytes(boot0))
        self.assertEqual(info['start'], pre)
        self.assertEqual(info['length'], length)
        self.assertEqual(len(info['image']), length)

    def test_preloader_fail_closed(self):
        with self.assertRaises(RuntimeError):
            s.parse_preloader_from_boot0(b'\x00' * 0x4000)


if __name__ == '__main__':
    unittest.main(verbosity=2)
