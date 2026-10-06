#!/usr/bin/env python3
"""Pure storage/GPT helpers for the TCL Flip 2 / T408DL recovery tool.

This module intentionally contains no USB code so the CLI and a future GUI can
share the same validation, partition lookup, dump classification, and
preloader-layout parsing logic.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import hashlib
import json
import struct
import zlib

BLOCK_SIZE = 0x200
GPT_SIGNATURE = b"EFI PART"


class GPTError(RuntimeError):
    pass


@dataclass(frozen=True)
class Partition:
    index: int
    name: str
    start: int
    size: int
    first_lba: int
    last_lba: int
    attributes: int = 0

    @property
    def end(self) -> int:
        return self.start + self.size

    def as_dict(self) -> dict:
        d = asdict(self)
        d["end"] = self.end
        return d


@dataclass(frozen=True)
class GPTTable:
    revision: int
    header_size: int
    header_crc: int
    entries_crc: int
    current_lba: int
    backup_lba: int
    first_usable_lba: int
    last_usable_lba: int
    entries_lba: int
    entry_count: int
    entry_size: int
    disk_guid: str
    partitions: tuple[Partition, ...]

    def by_name(self, name: str) -> Partition:
        wanted = name.casefold()
        matches = [p for p in self.partitions if p.name.casefold() == wanted]
        if not matches:
            raise GPTError(f"partition not found in live GPT: {name}")
        if len(matches) != 1:
            raise GPTError(f"partition name is not unique in live GPT: {name}")
        return matches[0]

    def by_start(self, start: int) -> Partition:
        matches = [p for p in self.partitions if p.start == start]
        if not matches:
            raise GPTError(f"0x{start:X} is not an exact live GPT partition start")
        if len(matches) != 1:
            raise GPTError(f"duplicate live GPT start address: 0x{start:X}")
        return matches[0]


# Firmware payloads that are useful for reconstructing/restoring a software
# release. Device-unique/calibration/state partitions are intentionally absent.
FIRMWARE_PARTITIONS = {
    "loader_ext1", "loader_ext2", "swversion", "oembin", "boot_para",
    "recovery", "sec1", "md1img", "md1dsp", "spmfw", "mcupmfw",
    "gz1", "gz2", "lk", "lk2", "boot", "vendor_boot", "logo", "dtbo",
    "vbmeta", "vbmeta_system", "vbmeta_vendor", "tee1", "tee2", "super",
}

# These can contain identifiers, calibration, provisioning, security state, or
# user/device-specific material. dump-all keeps them in private/.
PRIVATE_PARTITIONS = {
    "proinfo", "nvram", "persist", "oempersist", "frp", "nvcfg", "nvdata",
    "metadata", "protect1", "protect2", "md_udc", "seccfg", "efuse", "otp",
    "flashinfo", "userdata",
}

# Mostly transient/debug/update state. Still preserved by dump-all, but kept
# separate from a release-oriented firmware set.
STATE_PARTITIONS = {"otapkg", "para", "expdb", "cache"}


def _guid_le(raw: bytes) -> str:
    if len(raw) != 16:
        return raw.hex()
    d1, d2, d3 = struct.unpack_from("<IHH", raw, 0)
    d4 = raw[8:10].hex()
    d5 = raw[10:16].hex()
    return f"{d1:08x}-{d2:04x}-{d3:04x}-{d4}-{d5}"


def parse_primary_gpt(header_sector: bytes, entries: bytes, *, block_size: int = BLOCK_SIZE,
                      user_size: int | None = None) -> GPTTable:
    """Validate and parse a primary GPT header + entry array.

    `header_sector` must begin at LBA1. `entries` must contain exactly the byte
    count advertised by the header. CRC failures are fatal.
    """
    if len(header_sector) < block_size:
        raise GPTError(f"short GPT header sector: 0x{len(header_sector):X}")
    if header_sector[:8] != GPT_SIGNATURE:
        raise GPTError("primary GPT signature is invalid")

    revision, header_size, stored_header_crc = struct.unpack_from("<III", header_sector, 0x08)
    if header_size < 0x5C or header_size > block_size:
        raise GPTError(f"suspicious GPT header size 0x{header_size:X}")

    hdr = bytearray(header_sector[:header_size])
    struct.pack_into("<I", hdr, 0x10, 0)
    calc_header_crc = zlib.crc32(hdr) & 0xFFFFFFFF
    if calc_header_crc != stored_header_crc:
        raise GPTError(
            f"primary GPT header CRC mismatch: stored=0x{stored_header_crc:08X} "
            f"calculated=0x{calc_header_crc:08X}"
        )

    current_lba, backup_lba, first_usable, last_usable = struct.unpack_from("<QQQQ", header_sector, 0x18)
    disk_guid = _guid_le(header_sector[0x38:0x48])
    entries_lba = struct.unpack_from("<Q", header_sector, 0x48)[0]
    entry_count, entry_size, stored_entries_crc = struct.unpack_from("<III", header_sector, 0x50)

    if current_lba != 1:
        raise GPTError(f"unexpected primary GPT current_lba={current_lba}")
    if entry_count <= 0 or entry_count > 4096:
        raise GPTError(f"suspicious GPT entry count {entry_count}")
    if entry_size < 128 or entry_size > 1024 or (entry_size & 7):
        raise GPTError(f"suspicious GPT entry size 0x{entry_size:X}")

    expected_len = entry_count * entry_size
    if len(entries) != expected_len:
        raise GPTError(f"GPT entry-array length mismatch: 0x{len(entries):X} != 0x{expected_len:X}")

    calc_entries_crc = zlib.crc32(entries) & 0xFFFFFFFF
    if calc_entries_crc != stored_entries_crc:
        raise GPTError(
            f"GPT entry-array CRC mismatch: stored=0x{stored_entries_crc:08X} "
            f"calculated=0x{calc_entries_crc:08X}"
        )

    parts: list[Partition] = []
    starts: set[int] = set()
    names: set[str] = set()

    for index in range(entry_count):
        ent = entries[index * entry_size:(index + 1) * entry_size]
        if ent[:16] == b"\x00" * 16:
            continue
        first_lba, last_lba, attributes = struct.unpack_from("<QQQ", ent, 0x20)
        if last_lba < first_lba:
            raise GPTError(f"GPT entry {index} has invalid LBA geometry")
        if first_lba < first_usable or last_lba > last_usable:
            raise GPTError(f"GPT entry {index} lies outside usable-LBA bounds")

        name_raw = ent[0x38:min(entry_size, 0x80)]
        name = name_raw.decode("utf-16le", errors="ignore").split("\x00", 1)[0]
        if not name:
            name = f"gpt-entry-{index}"

        start = first_lba * block_size
        size = (last_lba - first_lba + 1) * block_size
        end = start + size
        if user_size is not None and end > user_size:
            raise GPTError(f"{name}: partition end 0x{end:X} exceeds USER size 0x{user_size:X}")
        if start in starts:
            raise GPTError(f"duplicate GPT start address 0x{start:X}")
        folded = name.casefold()
        if folded in names:
            raise GPTError(f"duplicate GPT partition name: {name}")
        starts.add(start)
        names.add(folded)
        parts.append(Partition(index=index + 1, name=name, start=start, size=size,
                               first_lba=first_lba, last_lba=last_lba, attributes=attributes))

    return GPTTable(
        revision=revision,
        header_size=header_size,
        header_crc=stored_header_crc,
        entries_crc=stored_entries_crc,
        current_lba=current_lba,
        backup_lba=backup_lba,
        first_usable_lba=first_usable,
        last_usable_lba=last_usable,
        entries_lba=entries_lba,
        entry_count=entry_count,
        entry_size=entry_size,
        disk_guid=disk_guid,
        partitions=tuple(parts),
    )


def parse_emmc_info(data: bytes) -> dict:
    if len(data) < 96:
        raise RuntimeError(f"unexpected GET_EMMC_INFO response length: 0x{len(data):X}")
    emmc_type, block_size = struct.unpack_from("<II", data, 0)
    boot1, boot2, rpmb, gp1, gp2, gp3, gp4, user = struct.unpack_from("<QQQQQQQQ", data, 8)
    cid = data[72:88]
    fwver = struct.unpack_from("<Q", data, 88)[0]
    return {
        "type": emmc_type,
        "block_size": block_size,
        "boot1": boot1,
        "boot2": boot2,
        "rpmb": rpmb,
        "gp1": gp1,
        "gp2": gp2,
        "gp3": gp3,
        "gp4": gp4,
        "user": user,
        "cid": cid.hex().upper(),
        "fwver": fwver,
    }


def classify_partition(name: str) -> str:
    n = name.casefold()
    if n in FIRMWARE_PARTITIONS:
        return "firmware"
    if n in PRIVATE_PARTITIONS:
        return "private"
    if n in STATE_PARTITIONS:
        return "state"
    return "other"


def validate_full_partition_image(partition: Partition, image_size: int) -> None:
    if image_size != partition.size:
        raise RuntimeError(
            f"{partition.name}: image must be a full partition dump: "
            f"0x{image_size:X} != 0x{partition.size:X}"
        )
    if image_size & (BLOCK_SIZE - 1):
        raise RuntimeError(f"{partition.name}: image is not 512-byte aligned")


def collision_safe_path(path: str | Path) -> Path:
    p = Path(path)
    if not p.exists():
        return p
    suffix = "".join(p.suffixes)
    stem = p.name[:-len(suffix)] if suffix else p.name
    for i in range(1, 10000):
        candidate = p.with_name(f"{stem}.{i}{suffix}")
        if not candidate.exists():
            return candidate
    raise RuntimeError(f"could not find a collision-safe name for {p}")


def collision_safe_dir(path: str | Path) -> Path:
    p = Path(path)
    if not p.exists():
        return p
    if p.is_dir() and not any(p.iterdir()):
        return p
    for i in range(1, 10000):
        candidate = p.with_name(f"{p.name}.{i}")
        if not candidate.exists():
            return candidate
    raise RuntimeError(f"could not find a collision-safe directory for {p}")


def sha256_file(path: str | Path, chunk_size: int = 4 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def format_gpt_table(table: GPTTable) -> str:
    lines = [
        f"GPT header CRC : PASS (0x{table.header_crc:08X})",
        f"entries CRC    : PASS (0x{table.entries_crc:08X})",
        f"entries        : {table.entry_count} x 0x{table.entry_size:X}",
        f"disk GUID      : {table.disk_guid}",
        "",
        f"{'#':>3}  {'name':<24} {'start':>12} {'size':>12} {'end':>12}  class",
        "-" * 88,
    ]
    for p in table.partitions:
        lines.append(
            f"{p.index:3}  {p.name:<24} 0x{p.start:010X} 0x{p.size:010X} "
            f"0x{p.end:010X}  {classify_partition(p.name)}"
        )
    lines.extend(["", f"Populated partitions: {len(table.partitions)}"])
    return "\n".join(lines)


def parse_preloader_from_boot0(boot0: bytes) -> dict:
    """Conservatively locate a MediaTek preloader using the eMMC boot layout.

    Layout checks mirror the well-known MediaTek/mtkclient flow:
      EMMC_BOOT -> BRLYT -> MMM\x01 -> length at +0x20.
    Any missing/inconsistent marker fails closed.
    """
    if len(boot0) < 0x1000:
        raise RuntimeError("boot0 dump is too small to contain the eMMC boot layout")
    if boot0[:9] != b"EMMC_BOOT":
        raise RuntimeError("boot0 does not begin with EMMC_BOOT; refusing to guess preloader offset")
    startbrlyt = struct.unpack_from("<I", boot0, 0x10)[0]
    if startbrlyt > len(boot0) - 0x20:
        raise RuntimeError(f"BRLYT offset 0x{startbrlyt:X} lies outside boot0")
    if boot0[startbrlyt:startbrlyt + 5] != b"BRLYT":
        raise RuntimeError("BRLYT marker missing at advertised offset")
    start = struct.unpack_from("<I", boot0, startbrlyt + 0x0C)[0]
    if start > len(boot0) - 0x24:
        raise RuntimeError(f"preloader offset 0x{start:X} lies outside boot0")
    if boot0[start:start + 4] != b"MMM\x01":
        raise RuntimeError("MMM\\x01 preloader marker missing at advertised offset")
    length = struct.unpack_from("<I", boot0, start + 0x20)[0]
    if length < 0x1000 or start + length > len(boot0):
        raise RuntimeError(f"invalid advertised preloader length 0x{length:X}")
    image = boot0[start:start + length]
    info_at = image.find(b"MTK_BLOADER_INFO")
    embedded_name = None
    if info_at >= 0 and info_at + 0x3D <= len(image):
        raw_name = image[info_at + 0x1B:info_at + 0x3D].rstrip(b"\x00")
        try:
            embedded_name = raw_name.decode("utf-8") or None
        except UnicodeDecodeError:
            embedded_name = None
    return {
        "start": start,
        "length": length,
        "sha256": hashlib.sha256(image).hexdigest(),
        "embedded_name": embedded_name,
        "image": image,
    }


def write_manifest(path: str | Path, payload: dict) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
