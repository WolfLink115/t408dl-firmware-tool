#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import json
import shlex
import shutil
import struct
import sys
import time
from pathlib import Path

import T408DL_preloader_catcher as stage1
import T408DL_preloader_stage3c_susbdl_zero as s3c
import T408DL_preloader_stage3e_wiko_stage1 as s3e
import T408DL_preloader_stage3f_jump_wiko as s3f
import T408DL_preloader_stage3g_xflash_sync as s3g
import t408dl_storage as storage


USB_TIMEOUT_MS = 5000

BOOT_TO = 0x010008
DEVICE_CTRL = 0x010009
GET_EMMC_INFO = 0x040001

# XFlash storage commands
WRITE_DATA = 0x010004
READ_DATA = 0x010005
GET_PACKET_LENGTH = 0x040007

# WRITE_DATA is allowed only when the requested range exactly
# matches a live GPT partition in eMMC USER.
# Boot0 / Boot1 / RPMB are NOT covered by this mechanism.

# XFlash storage identifiers
MTK_DA_STORAGE_EMMC = 1
MTK_DA_EMMC_PART_BOOT1 = 1
MTK_DA_EMMC_PART_BOOT2 = 2
MTK_DA_EMMC_PART_RPMB = 3
MTK_DA_EMMC_PART_USER = 8

READ_ADDR = 0x00000400
READ_LEN = 0x4000

STAGE2_PATH = Path(
    "wiko-da/WIKO_MT6739_STAGE2.WRITEPATCHED.bin"
)

STAGE2_ADDR = 0x40000000
STAGE2_LEN = 0x3A49C

STAGE2_SHA256 = (
    "accb6ae5004c2306de61cbe0407e45b7"
    "97d634d61d895085a98b7c45ea718414"
)


def load_stage2():
    data = STAGE2_PATH.read_bytes()

    print()
    print("[DA2] Patched Stage-2 verification")
    print(f"  path    = {STAGE2_PATH}")
    print(f"  address = 0x{STAGE2_ADDR:08X}")
    print(f"  length  = 0x{len(data):X}")

    digest = hashlib.sha256(data).hexdigest()

    print(f"  SHA256  = {digest}")

    if len(data) != STAGE2_LEN:
        raise RuntimeError(
            f"Stage2 length mismatch: "
            f"0x{len(data):X} != 0x{STAGE2_LEN:X}"
        )

    if digest != STAGE2_SHA256:
        raise RuntimeError(
            "Stage2 SHA256 mismatch"
        )

    print("  geometry/hash: PASS")

    return data


def send_stage2_data(ep_out, ep_in, data):
    """
    Equivalent to MTKClient xflash send_data():

        XFlash header
        raw data
        status

    We deliberately chunk the USB writes.
    """

    hdr = struct.pack(
        "<III",
        s3g.MAGIC,
        s3g.DT_PROTOCOL_FLOW,
        len(data),
    )

    print()
    print("[DA2] Data packet")
    print(
        f"  TX hdr: magic=0x{s3g.MAGIC:08X} "
        f"type={s3g.DT_PROTOCOL_FLOW} "
        f"len=0x{len(data):X}"
    )

    s3g.write_exact(
        ep_out,
        hdr,
    )

    max_packet = int(
        getattr(
            ep_out,
            "wMaxPacketSize",
            0x200,
        )
    )

    if max_packet <= 0:
        max_packet = 0x200

    print(
        f"  USB chunk size = "
        f"0x{max_packet:X}"
    )

    pos = 0

    while pos < len(data):
        chunk = data[
            pos:pos + max_packet
        ]

        s3g.write_exact(
            ep_out,
            chunk,
            USB_TIMEOUT_MS,
        )

        pos += len(chunk)

        if (
            pos == len(data)
            or (pos & 0xFFFF) == 0
        ):
            print(
                f"  uploaded "
                f"0x{pos:X}/0x{len(data):X}"
            )

    status = s3g.read_status(
        ep_in,
    )

    print(
        f"  data acceptance status = "
        f"0x{status:08X}"
    )

    if status != 0:
        raise RuntimeError(
            "DA2 data was rejected: "
            f"0x{status:08X}"
        )

    print(
        "  DA2 upload acceptance: PASS"
    )


def boot_stage2(ep_out, ep_in, stage2):
    print()
    print("=" * 72)
    print("DA2 — BOOT WIKO XFLASH STAGE-2")
    print("=" * 72)

    print(
        f"  BOOT_TO      = 0x{BOOT_TO:08X}"
    )
    print(
        f"  load address = 0x{STAGE2_ADDR:08X}"
    )
    print(
        f"  code length  = 0x{len(stage2):X}"
    )

    print()
    print("[1] BOOT_TO")

    s3g.xsend(
        ep_out,
        BOOT_TO,
    )

    status = s3g.read_status(
        ep_in,
    )

    print(
        f"  command status = "
        f"0x{status:08X}"
    )

    if status != 0:
        raise RuntimeError(
            f"BOOT_TO rejected: "
            f"0x{status:08X}"
        )

    print(
        "  BOOT_TO command: PASS"
    )

    # ------------------------------------------------------------
    # BOOT_TO parameter
    #
    # MTKClient sends this directly as an XFlash packet and DOES NOT
    # read a status between this packet and the following data packet.
    # ------------------------------------------------------------

    param = struct.pack(
        "<QQ",
        STAGE2_ADDR,
        len(stage2),
    )

    print()
    print("[2] BOOT_TO parameters")
    print(
        f"  address = "
        f"0x{STAGE2_ADDR:016X}"
    )
    print(
        f"  length  = "
        f"0x{len(stage2):016X}"
    )
    print(
        f"  payload = "
        f"{param.hex().upper()}"
    )

    s3g.xsend(
        ep_out,
        param,
    )

    # IMPORTANT:
    # No status read here.
    #
    # Next packet must be the actual Stage2 data.

    print()
    print("[3] Sending patched DA2 image")

    send_stage2_data(
        ep_out,
        ep_in,
        stage2,
    )

    # ------------------------------------------------------------
    # Stage2 execution result
    # ------------------------------------------------------------

    print()
    print("[4] Waiting for DA2 execution result")

    time.sleep(0.5)

    try:
        final = s3g.read_status(
            ep_in,
        )
    except Exception as exc:
        raise RuntimeError(
            "No valid post-BOOT_TO DA2 status "
            f"received: {exc}"
        )

    print(
        f"  execution status = "
        f"0x{final:08X}"
    )

    if final == 0:
        print(
            "  DA2 execution response: "
            "SUCCESS (0x00000000)"
        )

    elif final == s3g.SYNC_SIGNAL:
        print(
            "  DA2 execution response: "
            "SYNC_SIGNAL"
        )

    else:
        raise RuntimeError(
            f"Unexpected DA2 execution status "
            f"0x{final:08X}"
        )

    print()
    print(
        "  WIKO XFLASH DA2 EXECUTION: PROVEN"
    )



def devctrl_read(ep_out, ep_in, subcmd, name):
    print()
    print("=" * 72)
    print(f"DEVICE_CTRL: {name}")
    print("=" * 72)

    s3g.xsend(ep_out, DEVICE_CTRL)

    st = s3g.read_status(ep_in)
    print(f"  DEVICE_CTRL status = 0x{st:08X}")

    if st != 0:
        raise RuntimeError(
            f"{name}: DEVICE_CTRL rejected: 0x{st:08X}"
        )

    s3g.xsend(ep_out, subcmd)

    st = s3g.read_status(ep_in)
    print(f"  subcommand status  = 0x{st:08X}")

    if st != 0:
        raise RuntimeError(
            f"{name}: subcommand rejected: 0x{st:08X}"
        )

    dtype, data = s3g.xread_packet(ep_in)

    print(f"  datatype = {dtype}")
    print(f"  length   = 0x{len(data):X}")
    print(f"  raw      = {data.hex().upper()}")

    st = s3g.read_status(ep_in)
    print(f"  trailing status = 0x{st:08X}")

    if st != 0:
        raise RuntimeError(
            f"{name}: trailing status 0x{st:08X}"
        )

    return data


def decode_emmc_info(data):
    print()
    print("[Decoded eMMC information]")

    info = storage.parse_emmc_info(data)

    print(f"  type       = 0x{info['type']:X}")
    print(f"  block size = 0x{info['block_size']:X}")
    print(
        f"  Boot1      = 0x{info['boot1']:X} "
        f"({info['boot1'] / 1024 / 1024:.2f} MiB)"
    )
    print(
        f"  Boot2      = 0x{info['boot2']:X} "
        f"({info['boot2'] / 1024 / 1024:.2f} MiB)"
    )
    print(
        f"  RPMB       = 0x{info['rpmb']:X} "
        f"({info['rpmb'] / 1024 / 1024:.2f} MiB)"
    )
    print(f"  GP1        = 0x{info['gp1']:X}")
    print(f"  GP2        = 0x{info['gp2']:X}")
    print(f"  GP3        = 0x{info['gp3']:X}")
    print(f"  GP4        = 0x{info['gp4']:X}")
    print(
        f"  USER       = 0x{info['user']:X} "
        f"({info['user'] / 1024 / 1024 / 1024:.3f} GiB)"
    )
    print(f"  CID        = {info['cid']}")
    print(f"  FW version = 0x{info['fwver']:X}")

    return info



def send_ack_no_status(ep_out):
    """
    XFlash ACK packet used while receiving READ_DATA.

    TX only:
      magic = FEEEEEEF
      type  = protocol flow
      len   = 4
      value = 0

    No response is read here.
    """

    hdr = struct.pack(
        "<III",
        s3g.MAGIC,
        s3g.DT_PROTOCOL_FLOW,
        4,
    )

    s3g.write_exact(
        ep_out,
        hdr,
        USB_TIMEOUT_MS,
    )

    s3g.write_exact(
        ep_out,
        struct.pack("<I", 0),
        USB_TIMEOUT_MS,
    )


def read_xflash_header_zlp_safe(ep_in):
    """
    Read a 12-byte XFlash header while tolerating zero-length USB
    packets between bulk transfers.

    A ZLP is transport framing, not an XFlash packet.
    """

    hdr = bytearray()
    zlp_count = 0

    while len(hdr) < 12:
        need = 12 - len(hdr)

        try:
            chunk = bytes(
                ep_in.read(
                    need,
                    timeout=USB_TIMEOUT_MS,
                )
            )
        except Exception as exc:
            raise RuntimeError(
                f"USB error while reading XFlash header "
                f"at 0x{len(hdr):X}/0xC: {exc}"
            )

        if len(chunk) == 0:
            zlp_count += 1

            print(
                f"  USB ZLP while waiting for header "
                f"(count={zlp_count}); retrying..."
            )

            if zlp_count > 8:
                raise RuntimeError(
                    "Too many consecutive USB ZLPs while "
                    "waiting for XFlash header"
                )

            continue

        hdr.extend(chunk)

    if zlp_count:
        print(
            f"  skipped {zlp_count} USB ZLP(s)"
        )

    return bytes(hdr)


def read_xflash_raw_packet(ep_in):
    hdr = read_xflash_header_zlp_safe(
        ep_in,
    )

    magic, dtype, length = struct.unpack(
        "<III",
        hdr,
    )

    print(
        f"  RX hdr: magic=0x{magic:08X} "
        f"type={dtype} len=0x{length:X}"
    )

    if magic != s3g.MAGIC:
        raise RuntimeError(
            f"Invalid XFlash magic 0x{magic:08X}"
        )

    if length > 0x100000:
        raise RuntimeError(
            f"Suspicious XFlash packet length 0x{length:X}"
        )

    payload = s3g.read_exact(
        ep_in,
        length,
        USB_TIMEOUT_MS,
    )

    return dtype, payload


def read_user_sector0(ep_out, ep_in):
    print()
    print("=" * 72)
    print("GPT — READ PRIMARY PARTITION ENTRIES")
    print("=" * 72)

    print(f"  READ_DATA    = 0x{READ_DATA:08X}")
    print(f"  storage      = eMMC ({MTK_DA_STORAGE_EMMC})")
    print(f"  partition    = USER ({MTK_DA_EMMC_PART_USER})")
    print(f"  address      = 0x{READ_ADDR:016X}")
    print(f"  length       = 0x{READ_LEN:X} ({READ_LEN} bytes)")
    print()
    print("  operation    = READ-ONLY")
    print("  FORMAT       = not used by this operation")
    print("  ERASE        = not used by this operation")

    # --------------------------------------------------------
    # 1. READ_DATA command
    # --------------------------------------------------------

    print()
    print("[1] READ_DATA command")

    s3g.xsend(
        ep_out,
        READ_DATA,
    )

    st = s3g.read_status(
        ep_in,
    )

    print(
        f"  command status = "
        f"0x{st:08X}"
    )

    if st != 0:
        raise RuntimeError(
            f"READ_DATA rejected: 0x{st:08X}"
        )

    # --------------------------------------------------------
    # 2. READ_DATA parameters
    #
    # <IIQQ>
    #   storage
    #   section
    #   address
    #   size
    #
    # followed by 8 x u32 NandExtension values.
    #
    # For eMMC these extension values are all zero.
    # --------------------------------------------------------

    param = struct.pack(
        "<IIQQIIIIIIII",
        MTK_DA_STORAGE_EMMC,
        MTK_DA_EMMC_PART_USER,
        READ_ADDR,
        READ_LEN,

        0,  # cellusage
        0,  # addr_type
        0,  # bin_type
        0,  # region / format level
        0,  # sys_slc_percent
        0,  # usr_slc_percent
        0,  # phy_max_size
        0,  # reserved
    )

    print()
    print("[2] READ_DATA parameters")
    print(f"  parameter size = 0x{len(param):X}")
    print(f"  parameter raw  = {param.hex().upper()}")

    s3g.xsend(
        ep_out,
        param,
    )

    # send_param() semantics: first status acknowledges
    # receipt of the parameter packet.
    st = s3g.read_status(
        ep_in,
    )

    print(
        f"  parameter status = "
        f"0x{st:08X}"
    )

    if st != 0:
        raise RuntimeError(
            f"READ_DATA parameter rejected: 0x{st:08X}"
        )

    # Upstream XFlash cmd_read_data() consumes a second status
    # before the actual data stream begins.
    st = s3g.read_status(
        ep_in,
    )

    print(
        f"  read-start status = "
        f"0x{st:08X}"
    )

    if st != 0:
        raise RuntimeError(
            f"READ_DATA start rejected: 0x{st:08X}"
        )

    # --------------------------------------------------------
    # 3. Receive exactly one sector
    # --------------------------------------------------------

    print()
    print("[3] Receiving flash data")

    data = bytearray()

    while len(data) < READ_LEN:
        dtype, payload = read_xflash_raw_packet(
            ep_in,
        )

        print(
            f"  RX data packet: "
            f"{len(payload)} bytes"
        )

        # A 4-byte packet here can be an error/completion flag.
        if len(payload) == 4:
            flag = struct.unpack(
                "<I",
                payload,
            )[0]

            raise RuntimeError(
                f"Unexpected READ_DATA flag "
                f"0x{flag:08X} before receiving "
                f"0x{READ_LEN:X} bytes"
            )

        remaining = READ_LEN - len(data)

        if len(payload) > remaining:
            raise RuntimeError(
                f"DA returned too much data: "
                f"{len(payload)} > {remaining}"
            )

        data.extend(
            payload
        )

        # ACK this data packet exactly as XFlash expects.
        send_ack_no_status(
            ep_out,
        )

        print(
            f"  accumulated = "
            f"0x{len(data):X}/0x{READ_LEN:X}"
        )

    if len(data) != READ_LEN:
        raise RuntimeError(
            f"Expected 0x{READ_LEN:X} bytes, "
            f"received 0x{len(data):X}"
        )

    # --------------------------------------------------------
    # 4. Save the successfully received data FIRST
    # --------------------------------------------------------
    #
    # We have already received exactly READ_LEN bytes from the DA.
    # Preserve those bytes before attempting to observe the optional
    # final XFlash completion packet.
    # --------------------------------------------------------

    out = Path(
        "backups/emmc-user-gpt-entries.bin"
    )

    out.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    out.write_bytes(
        data
    )

    print()
    print("[4] READ RESULT")
    print(
        f"  bytes read  = "
        f"0x{len(data):X}"
    )
    print(
        f"  saved       = "
        f"{out}"
    )

    print()
    print("  first 64 bytes:")

    for off in range(
        0,
        min(64, len(data)),
        16,
    ):
        chunk = data[
            off:off + 16
        ]

        print(
            f"    {off:04X}: "
            f"{chunk.hex().upper()}"
        )

    sig = bytes(
        data[0x1FE:0x200]
    )

    print()
    print(
        f"  bytes[0x1FE:0x200] = "
        f"{sig.hex().upper()}"
    )

    if sig == b"\x55\xAA":
        print(
            "  legacy MBR signature 55AA: PRESENT"
        )
    else:
        print(
            "  legacy MBR signature 55AA: not present"
        )

    # --------------------------------------------------------
    # 5. Observe final completion packet if this DA provides it
    # --------------------------------------------------------

    print()
    print("[5] Observing READ_DATA completion")

    completion_seen = False

    try:
        dtype, final_payload = read_xflash_raw_packet(
            ep_in,
        )

        print(
            f"  completion payload = "
            f"{final_payload.hex().upper()}"
        )

        if len(final_payload) != 4:
            raise RuntimeError(
                "Unexpected completion payload length "
                f"{len(final_payload)}"
            )

        final_status = struct.unpack(
            "<I",
            final_payload,
        )[0]

        print(
            f"  completion status = "
            f"0x{final_status:08X}"
        )

        if final_status != 0:
            raise RuntimeError(
                f"READ_DATA completion failure: "
                f"0x{final_status:08X}"
            )

        completion_seen = True

    except Exception as exc:
        print(
            "  final completion packet: "
            "NOT OBSERVED"
        )
        print(
            f"  observation detail: {exc}"
        )
        print(
            "  The requested 0x200-byte data packet "
            "was already received and saved."
        )

    print()
    print(
        "  ONE-SECTOR eMMC USER READ: PROVEN"
    )

    if completion_seen:
        print(
            "  Final XFlash completion: PROVEN"
        )
    else:
        print(
            "  Final XFlash completion: UNOBSERVED"
        )

    return bytes(data)




def read_emmc_range(ep_out, ep_in, addr, size, outfile, label):
    import hashlib
    import time

    print()
    print("=" * 72)
    print(f"STORAGE READ — {label}")
    print("=" * 72)

    print(f"  storage   = eMMC")
    print(f"  partition = USER")
    print(f"  address   = 0x{addr:016X}")
    print(f"  length    = 0x{size:X} ({size / 1024 / 1024:.2f} MiB)")
    print(f"  output    = {outfile}")
    print()
    print("  operation  = READ-ONLY")
    print("  FORMAT     = not used")
    print("  ERASE      = not used")

    # --------------------------------------------------------
    # READ_DATA command
    # --------------------------------------------------------

    print()
    print("[1] READ_DATA command")

    s3g.xsend(
        ep_out,
        READ_DATA,
    )

    st = s3g.read_status(
        ep_in,
    )

    print(f"  command status = 0x{st:08X}")

    if st != 0:
        raise RuntimeError(
            f"{label}: READ_DATA rejected: 0x{st:08X}"
        )

    # --------------------------------------------------------
    # Parameter block
    # --------------------------------------------------------

    param = struct.pack(
        "<IIQQIIIIIIII",
        MTK_DA_STORAGE_EMMC,
        MTK_DA_EMMC_PART_USER,
        addr,
        size,

        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    )

    print()
    print("[2] READ_DATA parameters")
    print(f"  parameter size = 0x{len(param):X}")

    s3g.xsend(
        ep_out,
        param,
    )

    st = s3g.read_status(
        ep_in,
    )

    print(f"  parameter status = 0x{st:08X}")

    if st != 0:
        raise RuntimeError(
            f"{label}: parameter rejected: 0x{st:08X}"
        )

    st = s3g.read_status(
        ep_in,
    )

    print(f"  read-start status = 0x{st:08X}")

    if st != 0:
        raise RuntimeError(
            f"{label}: read start rejected: 0x{st:08X}"
        )

    # --------------------------------------------------------
    # Receive data
    # --------------------------------------------------------

    print()
    print("[3] Receiving flash data")

    data = bytearray()
    started = time.monotonic()

    while len(data) < size:
        dtype, payload = read_xflash_raw_packet(
            ep_in,
        )

        # XFlash READ_DATA can interleave 4-byte status packets
        # between actual data packets.
        #
        # status == 0:
        #     normal / continue
        #
        # status != 0:
        #     DA reported an error
        #
        # Do NOT ACK status packets.
        if len(payload) == 4:
            flag = struct.unpack(
                "<I",
                payload,
            )[0]

            print(
                f"  inter-packet status = "
                f"0x{flag:08X}"
            )

            if flag != 0:
                raise RuntimeError(
                    f"{label}: READ_DATA status "
                    f"0x{flag:08X} at "
                    f"0x{len(data):X}/0x{size:X}"
                )

            continue

        remaining = size - len(data)

        if len(payload) > remaining:
            raise RuntimeError(
                f"{label}: DA returned too much data: "
                f"0x{len(payload):X} > "
                f"remaining 0x{remaining:X}"
            )

        data.extend(
            payload
        )

        # ACK actual DATA packets only.
        send_ack_no_status(
            ep_out,
        )

        done = len(data)

        print(
            f"  received = "
            f"0x{done:X}/0x{size:X} "
            f"({done * 100.0 / size:.1f}%)"
        )

    elapsed = time.monotonic() - started

    if len(data) != size:
        raise RuntimeError(
            f"{label}: expected 0x{size:X}, "
            f"received 0x{len(data):X}"
        )

    # --------------------------------------------------------
    # Final READ_DATA completion status
    # --------------------------------------------------------

    print()
    print("[4] Final READ_DATA status")

    dtype, final_payload = read_xflash_raw_packet(
        ep_in,
    )

    if len(final_payload) != 4:
        raise RuntimeError(
            f"{label}: unexpected final packet length "
            f"0x{len(final_payload):X}"
        )

    final_status = struct.unpack(
        "<I",
        final_payload,
    )[0]

    print(
        f"  final status = "
        f"0x{final_status:08X}"
    )

    if final_status != 0:
        raise RuntimeError(
            f"{label}: final READ_DATA status "
            f"0x{final_status:08X}"
        )

    print(
        "  READ_DATA completion: PASS"
    )

    # --------------------------------------------------------
    # Save immediately
    # --------------------------------------------------------

    out = Path(outfile)

    out.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    out.write_bytes(
        data
    )

    digest = hashlib.sha256(
        data
    ).hexdigest()

    print()
    print("[5] BACKUP RESULT")
    print(f"  bytes  = 0x{len(data):X}")
    print(f"  file   = {out}")
    print(f"  SHA256 = {digest}")
    print(f"  time   = {elapsed:.3f}s")

    print()
    print("  first 64 bytes:")

    for off in range(0, min(64, len(data)), 16):
        print(
            f"    {off:04X}: "
            f"{data[off:off+16].hex().upper()}"
        )

    print()
    print(f"  {label} READ: PROVEN")

    # The TCL/Wiko DA has not emitted the optional final completion
    # packet in our proven reads. Do not block waiting for it here.

    return bytes(data), digest



def read_emmc_area_stream(
    ep_out,
    ep_in,
    addr,
    size,
    outfile,
    label,
    *,
    emmc_part=MTK_DA_EMMC_PART_USER,
    area_name="USER",
    collect=False,
    collision_safe=True,
):
    """Stream an XFlash READ_DATA transfer directly to disk.

    This is the large-partition path used by named dumps, dump-firmware,
    dump-all, and read-only Boot0/Boot1 access. It never buffers the entire
    image unless collect=True is explicitly requested for a small structure.
    """
    if size <= 0:
        raise RuntimeError("read size must be > 0")
    if addr < 0:
        raise RuntimeError("read address must be >= 0")
    if addr & 0x1FF or size & 0x1FF:
        raise RuntimeError("storage reads must be 512-byte aligned")

    out = None
    if outfile is not None:
        out = Path(outfile)
        if collision_safe:
            out = storage.collision_safe_path(out)
        out.parent.mkdir(parents=True, exist_ok=True)

    print()
    print("=" * 72)
    print(f"STREAMING STORAGE READ — {label}")
    print("=" * 72)
    print("  storage   = eMMC")
    print(f"  area      = {area_name} (selector {emmc_part})")
    print(f"  address   = 0x{addr:016X}")
    print(f"  length    = 0x{size:X} ({size / 1024 / 1024:.2f} MiB)")
    if out is not None:
        print(f"  output    = {out}")
    else:
        print("  output    = memory-only")
    print("  operation = READ-ONLY")

    s3g.xsend(ep_out, READ_DATA)
    st = s3g.read_status(ep_in)
    if st != 0:
        raise RuntimeError(f"{label}: READ_DATA rejected: 0x{st:08X}")

    param = struct.pack(
        "<IIQQIIIIIIII",
        MTK_DA_STORAGE_EMMC,
        emmc_part,
        addr,
        size,
        0, 0, 0, 0, 0, 0, 0, 0,
    )
    s3g.xsend(ep_out, param)
    st = s3g.read_status(ep_in)
    if st != 0:
        raise RuntimeError(f"{label}: parameter rejected: 0x{st:08X}")
    st = s3g.read_status(ep_in)
    if st != 0:
        raise RuntimeError(f"{label}: read start rejected: 0x{st:08X}")

    digest = hashlib.sha256()
    gathered = bytearray() if collect else None
    done = 0
    started = time.monotonic()
    next_report = min(size, 0x1000000)  # 16 MiB

    partial = None
    if out is not None:
        partial = storage.collision_safe_path(out.with_name(out.name + ".partial"))
    fh = partial.open("xb") if partial is not None else None
    transfer_ok = False
    try:
        while done < size:
            dtype, payload = read_xflash_raw_packet(ep_in)

            if len(payload) == 4:
                flag = struct.unpack("<I", payload)[0]
                if flag != 0:
                    raise RuntimeError(
                        f"{label}: READ_DATA status 0x{flag:08X} "
                        f"at 0x{done:X}/0x{size:X}"
                    )
                continue

            remaining = size - done
            if len(payload) > remaining:
                raise RuntimeError(
                    f"{label}: DA returned too much data: "
                    f"0x{len(payload):X} > remaining 0x{remaining:X}"
                )
            if not payload:
                raise RuntimeError(f"{label}: zero-length data payload")

            if fh is not None:
                fh.write(payload)
            digest.update(payload)
            if gathered is not None:
                gathered.extend(payload)
            done += len(payload)
            send_ack_no_status(ep_out)

            if done >= next_report or done == size:
                elapsed = time.monotonic() - started
                print(
                    f"  received = 0x{done:X}/0x{size:X} "
                    f"({done * 100.0 / size:.1f}%, {elapsed:.1f}s)"
                )
                while next_report <= done:
                    next_report += 0x1000000

        dtype, final_payload = read_xflash_raw_packet(ep_in)
        if len(final_payload) != 4:
            raise RuntimeError(
                f"{label}: unexpected final packet length 0x{len(final_payload):X}"
            )
        final_status = struct.unpack("<I", final_payload)[0]
        if final_status != 0:
            raise RuntimeError(
                f"{label}: final READ_DATA status 0x{final_status:08X}"
            )
        transfer_ok = True
    except Exception:
        if fh is not None:
            fh.flush()
        raise
    finally:
        if fh is not None:
            fh.close()

    if out is not None and partial is not None and transfer_ok:
        partial.rename(out)

    hexdigest = digest.hexdigest()
    elapsed = time.monotonic() - started
    print("  READ_DATA completion: PASS")
    print(f"  SHA256 = {hexdigest}")
    print(f"  time   = {elapsed:.3f}s")
    if out is not None:
        print(f"  file   = {out}")

    return (
        bytes(gathered) if gathered is not None else None,
        hexdigest,
        out,
    )


def read_emmc_bytes(ep_out, ep_in, addr, size, label, *, emmc_part=MTK_DA_EMMC_PART_USER, area_name="USER"):
    data, digest, _ = read_emmc_area_stream(
        ep_out,
        ep_in,
        addr,
        size,
        None,
        label,
        emmc_part=emmc_part,
        area_name=area_name,
        collect=True,
        collision_safe=False,
    )
    return data, digest



def _write_xflash_param_frame(ep_out, payload):
    """Write one framed XFlash parameter without consuming status."""
    hdr = struct.pack(
        "<III",
        s3g.MAGIC,
        s3g.DT_PROTOCOL_FLOW,
        len(payload),
    )

    s3g.write_exact(
        ep_out,
        hdr,
        USB_TIMEOUT_MS,
    )

    pos = 0

    while pos < len(payload):
        chunk = payload[pos:pos + 0x200]

        s3g.write_exact(
            ep_out,
            chunk,
            USB_TIMEOUT_MS,
        )

        pos += len(chunk)


def _send_param_group(ep_out, ep_in, payloads, label):
    """
    Mirror MTKClient send_param():

        send every framed parameter
        then consume one status packet
    """

    for payload in payloads:
        _write_xflash_param_frame(
            ep_out,
            payload,
        )

    st = s3g.read_status(
        ep_in,
    )

    print(
        f"  {label} status = "
        f"0x{st:08X}"
    )

    if st != 0:
        raise RuntimeError(
            f"{label} rejected: "
            f"0x{st:08X}"
        )


def get_write_packet_length(ep_out, ep_in):
    data = devctrl_read(
        ep_out,
        ep_in,
        GET_PACKET_LENGTH,
        "GET_PACKET_LENGTH",
    )

    if len(data) < 8:
        raise RuntimeError(
            f"GET_PACKET_LENGTH returned "
            f"only 0x{len(data):X} bytes"
        )

    write_len, read_len = struct.unpack_from(
        "<II",
        data,
        0,
    )

    print()
    print("[Packet lengths]")
    print(
        f"  write = 0x{write_len:X}"
    )
    print(
        f"  read  = 0x{read_len:X}"
    )

    if (
        write_len < 0x200
        or write_len > 0x400000
        or (write_len & 0x1FF)
    ):
        raise RuntimeError(
            f"Suspicious DA write packet length "
            f"0x{write_len:X}"
        )

    return write_len



def get_live_gpt_table(ep_out, ep_in, emmc_info=None, *, verbose=True):
    """Read, CRC-validate, and parse the primary GPT from eMMC USER."""
    if verbose:
        print()
        print("=" * 72)
        print("LIVE GPT")
        print("=" * 72)

    header, _ = read_emmc_bytes(
        ep_out,
        ep_in,
        0x200,
        0x200,
        "live GPT header",
    )

    if header[:8] != b"EFI PART":
        raise RuntimeError("Primary GPT signature is invalid")

    entries_lba = struct.unpack_from("<Q", header, 0x48)[0]
    entry_count = struct.unpack_from("<I", header, 0x50)[0]
    entry_size = struct.unpack_from("<I", header, 0x54)[0]

    if entry_count <= 0 or entry_count > 4096:
        raise RuntimeError(f"Suspicious GPT entry count {entry_count}")
    if entry_size < 128 or entry_size > 1024 or (entry_size & 7):
        raise RuntimeError(f"Suspicious GPT entry size 0x{entry_size:X}")

    entries_len = entry_count * entry_size
    entries_addr = entries_lba * 0x200
    entries, _ = read_emmc_bytes(
        ep_out,
        ep_in,
        entries_addr,
        entries_len,
        "live GPT entries",
    )

    user_size = None
    if isinstance(emmc_info, dict):
        user_size = emmc_info.get("user")

    table = storage.parse_primary_gpt(
        header,
        entries,
        block_size=0x200,
        user_size=user_size,
    )

    if verbose:
        print()
        print(storage.format_gpt_table(table))
        print("  GPT validation: PASS")

    return table


def get_live_gpt_partitions(ep_out, ep_in, emmc_info=None):
    """Compatibility map keyed by exact byte start address."""
    table = get_live_gpt_table(ep_out, ep_in, emmc_info, verbose=True)
    return {
        p.start: {
            "name": p.name,
            "start": p.start,
            "size": p.size,
            "first_lba": p.first_lba,
            "last_lba": p.last_lba,
        }
        for p in table.partitions
    }


def validate_gpt_write_target(
    ep_out,
    ep_in,
    addr,
    part_size,
):
    partitions = get_live_gpt_partitions(
        ep_out,
        ep_in,
    )

    part = partitions.get(
        addr
    )

    if part is None:
        raise RuntimeError(
            f"0x{addr:X} is not the exact start "
            f"of a live GPT USER partition"
        )

    if part_size != part["size"]:
        raise RuntimeError(
            f"{part['name']}: requested size "
            f"0x{part_size:X} does not match "
            f"live GPT size 0x{part['size']:X}"
        )

    print()
    print("[GPT WRITE TARGET]")
    print(
        f"  name       = "
        f"{part['name']}"
    )
    print(
        f"  start      = "
        f"0x{part['start']:016X}"
    )
    print(
        f"  size       = "
        f"0x{part['size']:X}"
    )
    print(
        f"  first LBA  = "
        f"0x{part['first_lba']:X}"
    )
    print(
        f"  last LBA   = "
        f"0x{part['last_lba']:X}"
    )

    return part


def write_emmc_range_verify(
    ep_out,
    ep_in,
    addr,
    part_size,
    image_path,
):
    """Write one exact live-GPT USER partition and verify it by full SHA-256 readback.

    The source file and readback are streamed; even large images such as super
    are not loaded wholesale into RAM.
    """
    part = validate_gpt_write_target(ep_out, ep_in, addr, part_size)
    name = part["name"]

    image = Path(image_path)
    if not image.is_file():
        raise RuntimeError(f"image not found: {image}")

    image_size = image.stat().st_size
    if image_size != part_size:
        raise RuntimeError(
            f"{name}: image must be a full partition dump: "
            f"0x{image_size:X} != 0x{part_size:X}"
        )
    if image_size & 0x1FF:
        raise RuntimeError(f"{name}: image is not 512-byte aligned")

    source_sha = storage.sha256_file(image)

    print()
    print("=" * 72)
    print(f"WRITE-VERIFY — {name}")
    print("=" * 72)
    print(f"  address        = 0x{addr:016X}")
    print(f"  partition size = 0x{part_size:X}")
    print(f"  image          = {image}")
    print(f"  image size     = 0x{image_size:X}")
    print(f"  source SHA256  = {source_sha}")
    print()
    print("  FORMAT = NOT IMPLEMENTED")
    print("  ERASE  = NOT IMPLEMENTED")
    print("  eMMC Boot0/Boot1/RPMB writes = DISABLED")

    safe_name = "".join(ch if ch.isalnum() else "-" for ch in name.upper()).strip("-")
    expected_token = f"WRITE-{safe_name}"
    token = input(f"Type {expected_token} to arm this partition: ").strip()
    if token != expected_token:
        print("  confirmation mismatch; write cancelled")
        return False

    packet_len = get_write_packet_length(ep_out, ep_in)

    print()
    print("[1] WRITE_DATA command")
    s3g.xsend(ep_out, WRITE_DATA)
    st = s3g.read_status(ep_in)
    print(f"  command status = 0x{st:08X}")
    if st != 0:
        raise RuntimeError(f"WRITE_DATA rejected: 0x{st:08X}")

    param = struct.pack(
        "<IIQQIIIIIIII",
        MTK_DA_STORAGE_EMMC,
        MTK_DA_EMMC_PART_USER,
        addr,
        image_size,
        0, 0, 0, 0, 0, 0, 0, 0,
    )

    print()
    print("[2] WRITE_DATA parameters")
    print(f"  parameter size = 0x{len(param):X}")
    _send_param_group(ep_out, ep_in, [param], "write parameter")

    print()
    print("[3] Streaming flash data")
    pos = 0
    started = time.monotonic()
    write_hash = hashlib.sha256()

    with image.open("rb") as rf:
        while pos < image_size:
            want = min(packet_len, image_size - pos)
            chunk = rf.read(want)
            if len(chunk) != want:
                raise RuntimeError(
                    f"{name}: source file changed/short-read at 0x{pos:X}: "
                    f"0x{len(chunk):X}/0x{want:X}"
                )
            if len(chunk) & 0x1FF:
                raise RuntimeError(
                    f"internal error: chunk 0x{len(chunk):X} is not 512-byte aligned"
                )
            checksum = sum(chunk) & 0xFFFF
            _send_param_group(
                ep_out,
                ep_in,
                [struct.pack("<I", 0), struct.pack("<I", checksum), chunk],
                f"chunk@0x{pos:X}",
            )
            write_hash.update(chunk)
            pos += len(chunk)
            print(
                f"  written = 0x{pos:X}/0x{image_size:X} "
                f"({pos * 100.0 / image_size:.1f}%)"
            )

    streamed_source_sha = write_hash.hexdigest()
    if streamed_source_sha != source_sha:
        raise RuntimeError(
            f"{name}: source file changed while writing; "
            f"pre-hash={source_sha} streamed-hash={streamed_source_sha}"
        )

    print()
    print("[4] Final WRITE_DATA status")
    st = s3g.read_status(ep_in)
    print(f"  final status = 0x{st:08X}")
    if st != 0:
        raise RuntimeError(f"{name}: final WRITE_DATA status 0x{st:08X}")
    elapsed = time.monotonic() - started
    print(f"  WRITE_DATA completion: PASS ({elapsed:.3f}s)")

    print()
    print("[5] Full streaming read-back verification")
    verify_file = Path("backups") / f"readback-{name}-after-write.bin"
    _, readback_sha, actual_verify_file = read_emmc_area_stream(
        ep_out,
        ep_in,
        addr,
        image_size,
        verify_file,
        f"{name} post-write verify",
        emmc_part=MTK_DA_EMMC_PART_USER,
        area_name="USER",
        collect=False,
        collision_safe=True,
    )

    print()
    print(f"  source SHA256   = {source_sha}")
    print(f"  readback SHA256 = {readback_sha}")
    print(f"  readback file   = {actual_verify_file}")
    if readback_sha != source_sha:
        raise RuntimeError(
            f"{name}: READ-BACK SHA256 MISMATCH — STOP. "
            "Do not write another partition."
        )

    print()
    print(f"  {name}: WRITE + FULL READ-BACK VERIFY = PASS")
    return True


def parse_int(value):
    return int(value, 0)


def summarize_blob(data):
    import hashlib

    nonzero = sum(
        1 for b in data
        if b != 0
    )

    first_nonzero = next(
        (
            i
            for i, b in enumerate(data)
            if b != 0
        ),
        None,
    )

    digest = hashlib.sha256(
        data
    ).hexdigest()

    return {
        "sha256": digest,
        "nonzero": nonzero,
        "first_nonzero": first_nonzero,
    }


def readonly_probe(ep_out, ep_in, addr, size, label):
    data, digest = read_emmc_range(
        ep_out,
        ep_in,
        addr,
        size,
        f"backups/shell-probe-{addr:016X}-{size:X}.bin",
        label,
    )

    summary = summarize_blob(
        data
    )

    print()
    print("[PROBE SUMMARY]")
    print(
        f"  address       = 0x{addr:016X}"
    )
    print(
        f"  length        = 0x{size:X}"
    )
    print(
        f"  SHA256        = {summary['sha256']}"
    )
    print(
        f"  nonzero bytes = "
        f"{summary['nonzero']}/{len(data)}"
    )

    if summary["first_nonzero"] is None:
        print(
            "  first nonzero = NONE"
        )
    else:
        print(
            f"  first nonzero = "
            f"0x{summary['first_nonzero']:X}"
        )

    print(
        f"  first32       = "
        f"{data[:32].hex().upper()}"
    )

    return data


def run_damage_sweep(ep_out, ep_in):
    probes = [
        (
            "GPT entries",
            0x00000400,
            0x10000,
        ),
        (
            "nvram",
            0x00800000,
            0x10000,
        ),
        (
            "persist",
            0x01000000,
            0x10000,
        ),
        (
            "nvcfg",
            0x0A880000,
            0x10000,
        ),
        (
            "nvdata",
            0x0B080000,
            0x10000,
        ),
        (
            "seccfg",
            0x11800000,
            0x10000,
        ),
        (
            "efuse",
            0x12200000,
            0x10000,
        ),
        (
            "lk",
            0x19480000,
            0x10000,
        ),
        (
            "lk2",
            0x19680000,
            0x10000,
        ),
        (
            "boot",
            0x19880000,
            0x10000,
        ),
        (
            "vbmeta",
            0x20080000,
            0x10000,
        ),
        (
            "super",
            0x21000000,
            0x10000,
        ),
        (
            "backup GPT",
            0x3A3DFFE00,
            0x200,
        ),
    ]

    results = []

    print()
    print("=" * 72)
    print("READ-ONLY STORAGE SAMPLE SWEEP")
    print("=" * 72)

    for name, addr, size in probes:
        outfile = (
            f"backups/sweep-"
            f"{name.lower().replace(' ', '-')}.bin"
        )

        data, digest = read_emmc_range(
            ep_out,
            ep_in,
            addr,
            size,
            outfile,
            name,
        )

        info = summarize_blob(
            data
        )

        results.append(
            (
                name,
                addr,
                size,
                info,
            )
        )

    print()
    print("=" * 72)
    print("STORAGE SAMPLE SWEEP SUMMARY")
    print("=" * 72)

    for name, addr, size, info in results:
        if info["nonzero"] == 0:
            state = "ZERO"
        else:
            state = "DATA"

        first = info["first_nonzero"]

        if first is None:
            first_text = "-"
        else:
            first_text = f"0x{first:X}"

        print(
            f"{name:12s}  "
            f"0x{addr:010X}  "
            f"{state:4s}  "
            f"nonzero={info['nonzero']:6d}/{size:<6d}  "
            f"first={first_text}"
        )

    print()
    print(
        "Storage sample sweep complete. All reads were read-only."
    )



def _validate_user_read_bounds(addr, size, emmc_info):
    if addr < 0 or size <= 0:
        raise RuntimeError("address must be >= 0 and size must be > 0")
    if addr & 0x1FF or size & 0x1FF:
        raise RuntimeError("USER reads must be 512-byte aligned")
    user_size = emmc_info.get("user") if isinstance(emmc_info, dict) else None
    if user_size is not None and addr + size > user_size:
        raise RuntimeError(
            f"read end 0x{addr + size:X} exceeds eMMC USER size 0x{user_size:X}"
        )


def _partition_or_fail(table, name):
    try:
        return table.by_name(name)
    except Exception as exc:
        raise RuntimeError(str(exc)) from exc


def print_partition_info(part):
    print()
    print(f"Partition: {part.name}")
    print(f"Index:     {part.index}")
    print(f"Class:     {storage.classify_partition(part.name)}")
    print(f"Start:     0x{part.start:016X}")
    print(f"End:       0x{part.end:016X}")
    print(f"Size:      0x{part.size:X} ({part.size / 1024 / 1024:.2f} MiB)")
    print(f"First LBA: 0x{part.first_lba:X}")
    print(f"Last LBA:  0x{part.last_lba:X}")


def dump_named_partition(ep_out, ep_in, table, name, outfile=None):
    part = _partition_or_fail(table, name)
    if outfile is None:
        outfile = f"{part.name}.bin"
    return read_emmc_area_stream(
        ep_out,
        ep_in,
        part.start,
        part.size,
        outfile,
        f"partition {part.name}",
        emmc_part=MTK_DA_EMMC_PART_USER,
        area_name="USER",
        collect=False,
        collision_safe=True,
    )


def dump_hardware_area(ep_out, ep_in, emmc_info, which, outfile=None):
    if not isinstance(emmc_info, dict):
        raise RuntimeError("eMMC geometry is unavailable")

    aliases = {
        "boot0": (MTK_DA_EMMC_PART_BOOT1, "BOOT1", "boot1", "mmcblk0boot0.bin"),
        "mmcblk0boot0": (MTK_DA_EMMC_PART_BOOT1, "BOOT1", "boot1", "mmcblk0boot0.bin"),
        "boot1": (MTK_DA_EMMC_PART_BOOT2, "BOOT2", "boot2", "mmcblk0boot1.bin"),
        "mmcblk0boot1": (MTK_DA_EMMC_PART_BOOT2, "BOOT2", "boot2", "mmcblk0boot1.bin"),
    }
    key = which.casefold()
    if key not in aliases:
        raise RuntimeError("dump-hw supports only boot0/mmcblk0boot0 and boot1/mmcblk0boot1")
    selector, area_name, size_key, default_name = aliases[key]
    size = int(emmc_info.get(size_key, 0) or 0)
    if size <= 0:
        raise RuntimeError(f"GET_EMMC_INFO reported zero size for {area_name}")
    if outfile is None:
        outfile = default_name

    return read_emmc_area_stream(
        ep_out,
        ep_in,
        0,
        size,
        outfile,
        f"eMMC {area_name} ({default_name})",
        emmc_part=selector,
        area_name=area_name,
        collect=False,
        collision_safe=True,
    )


def dump_preloader_from_boot0(ep_out, ep_in, emmc_info, outfile):
    if not isinstance(emmc_info, dict):
        raise RuntimeError("eMMC geometry is unavailable")
    size = int(emmc_info.get("boot1", 0) or 0)
    if size <= 0:
        raise RuntimeError("GET_EMMC_INFO reported zero BOOT1 size")
    if size > 0x1000000:
        raise RuntimeError(f"refusing unexpected BOOT1 size 0x{size:X}")

    boot0, boot0_sha = read_emmc_bytes(
        ep_out,
        ep_in,
        0,
        size,
        "eMMC BOOT1 preloader-layout read",
        emmc_part=MTK_DA_EMMC_PART_BOOT1,
        area_name="BOOT1/mmcblk0boot0",
    )
    info = storage.parse_preloader_from_boot0(boot0)
    out = storage.collision_safe_path(Path(outfile))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(info["image"])

    print()
    print("PRELOADER EXTRACTION: PASS")
    print(f"  boot0 SHA256     = {boot0_sha}")
    print(f"  preloader offset = 0x{info['start']:X}")
    print(f"  preloader length = 0x{info['length']:X}")
    print(f"  preloader SHA256 = {info['sha256']}")
    if info.get("embedded_name"):
        print(f"  embedded name    = {info['embedded_name']}")
    print(f"  output           = {out}")
    return out, info


def _write_dump_sidecars(root, table, emmc_info, records, *, include_device_id=False):
    root = Path(root)
    gpt_text = storage.format_gpt_table(table) + "\n"
    (root / "GPT.txt").write_text(gpt_text, encoding="utf-8")

    manifest_emmc = {
        "block_size": emmc_info.get("block_size"),
        "boot1_size": emmc_info.get("boot1"),
        "boot2_size": emmc_info.get("boot2"),
        "rpmb_size": emmc_info.get("rpmb"),
        "user_size": emmc_info.get("user"),
    }
    if include_device_id:
        manifest_emmc["cid"] = emmc_info.get("cid")
        manifest_emmc["fwver"] = emmc_info.get("fwver")

    manifest = {
        "tool": "t408dl",
        "note": "Images are preserved exactly as read; stock/modification state is not inferred.",
        "emmc": manifest_emmc,
        "gpt": {
            "header_crc": f"0x{table.header_crc:08X}",
            "entries_crc": f"0x{table.entries_crc:08X}",
            "disk_guid": table.disk_guid,
            "entry_count": table.entry_count,
            "entry_size": table.entry_size,
            "partitions": [p.as_dict() | {"class": storage.classify_partition(p.name)} for p in table.partitions],
        },
        "files": records,
    }
    storage.write_manifest(root / "manifest.json", manifest)

    with (root / "SHA256SUMS").open("w", encoding="utf-8") as wf:
        for rec in sorted(records, key=lambda r: r["path"]):
            if rec.get("sha256") and rec.get("path"):
                wf.write(f"{rec['sha256']}  {rec['path']}\n")


def _save_primary_gpt_image(ep_out, ep_in, table, root):
    end = table.entries_lba * 0x200 + table.entry_count * table.entry_size
    length = (end + 0x1FF) & ~0x1FF
    _, digest, out = read_emmc_area_stream(
        ep_out,
        ep_in,
        0,
        length,
        Path(root) / "GPT.bin",
        "primary GPT image",
        emmc_part=MTK_DA_EMMC_PART_USER,
        area_name="USER",
        collect=False,
        collision_safe=True,
    )
    return {
        "kind": "gpt",
        "path": str(out.relative_to(root)),
        "sha256": digest,
        "size": length,
    }


def dump_partition_collection(ep_out, ep_in, emmc_info, directory, *, firmware_only):
    table = get_live_gpt_table(ep_out, ep_in, emmc_info, verbose=False)
    root = storage.collision_safe_dir(Path(directory))
    root.mkdir(parents=True, exist_ok=True)
    print(f"Dump directory: {root}")

    selected = []
    for part in table.partitions:
        category = storage.classify_partition(part.name)
        if firmware_only:
            if category == "firmware":
                selected.append((part, category))
        else:
            selected.append((part, category))

    total = sum(p.size for p, _ in selected)
    hw_total = int(emmc_info.get("boot1", 0) or 0) + int(emmc_info.get("boot2", 0) or 0)
    required = total + hw_total + 0x10000000  # 256 MiB working margin
    free = shutil.disk_usage(root).free
    print(
        f"Selected {len(selected)} GPT partitions, total "
        f"{total / 1024 / 1024 / 1024:.3f} GiB"
    )
    print(f"Free disk space: {free / 1024 / 1024 / 1024:.3f} GiB")
    if free < required:
        raise RuntimeError(
            f"insufficient free space: need at least "
            f"{required / 1024 / 1024 / 1024:.3f} GiB including safety margin"
        )

    if not firmware_only:
        print("dump-all includes userdata/private/device-specific state.")
        token = input("Type DUMP-ALL to continue: ").strip()
        if token != "DUMP-ALL":
            print("dump-all cancelled")
            return None

    records = []
    records.append(_save_primary_gpt_image(ep_out, ep_in, table, root))

    for part, category in selected:
        subdir = root / category
        subdir.mkdir(parents=True, exist_ok=True)
        target = subdir / f"{part.name}.bin"
        _, digest, actual = read_emmc_area_stream(
            ep_out,
            ep_in,
            part.start,
            part.size,
            target,
            f"partition {part.name}",
            emmc_part=MTK_DA_EMMC_PART_USER,
            area_name="USER",
            collect=False,
            collision_safe=True,
        )
        records.append({
            "kind": "gpt-partition",
            "partition": part.name,
            "class": category,
            "start": part.start,
            "size": part.size,
            "path": str(actual.relative_to(root)),
            "sha256": digest,
        })

    # Full eMMC boot hardware areas are useful recovery material and are
    # intentionally read-only. Include them in both firmware and full dumps.
    hwdir = root / "hardware"
    hwdir.mkdir(parents=True, exist_ok=True)
    boot0_path = None
    for alias in ("boot0", "boot1"):
        default = "mmcblk0boot0.bin" if alias == "boot0" else "mmcblk0boot1.bin"
        _, digest, actual = dump_hardware_area(
            ep_out, ep_in, emmc_info, alias, hwdir / default
        )
        if alias == "boot0":
            boot0_path = actual
        records.append({
            "kind": "emmc-hardware-area",
            "area": alias,
            "path": str(actual.relative_to(root)),
            "size": actual.stat().st_size,
            "sha256": digest,
        })

    # Extract from the already-preserved BOOT1/mmcblk0boot0 image. The parser
    # deliberately fails closed unless EMMC_BOOT -> BRLYT -> MMM\x01 is
    # self-consistent and advertises an in-range length.
    try:
        if boot0_path is None:
            raise RuntimeError("mmcblk0boot0 dump is unavailable")
        pre = storage.parse_preloader_from_boot0(boot0_path.read_bytes())
        preloader_path = storage.collision_safe_path(hwdir / "preloader_raw.img")
        preloader_path.write_bytes(pre["image"])
        print("Preloader extraction from saved mmcblk0boot0: PASS")
        print(f"  offset = 0x{pre['start']:X}")
        print(f"  length = 0x{pre['length']:X}")
        print(f"  SHA256 = {pre['sha256']}")
        records.append({
            "kind": "preloader",
            "path": str(preloader_path.relative_to(root)),
            "size": pre["length"],
            "offset_in_mmcblk0boot0": pre["start"],
            "embedded_name": pre.get("embedded_name"),
            "sha256": pre["sha256"],
        })
    except Exception as exc:
        print(f"Preloader extraction skipped/fail-closed: {exc}")

    _write_dump_sidecars(
        root,
        table,
        emmc_info,
        records,
        include_device_id=not firmware_only,
    )
    print()
    print("Dump complete.")
    print(f"  directory = {root}")
    print(f"  manifest  = {root / 'manifest.json'}")
    print(f"  hashes    = {root / 'SHA256SUMS'}")
    return root

def stage2_writeverify_shell(ep_out, ep_in, emmc_info=None):
    print()
    print("=" * 72)
    print("T408DL XFLASH RECOVERY SHELL")
    print("=" * 72)
    print()
    print("Persistent XFlash DA2 session is ACTIVE.")
    print("Live-GPT partition operations and streaming dumps are available.")
    print("Type 'help' for commands.")
    print()
    print("WRITE_DATA = ENABLED FOR EXACT LIVE GPT USER PARTITIONS")
    print("BOOT0 / BOOT1 = READ-ONLY")
    print("RPMB WRITE = DISABLED")
    print("FORMAT / ERASE = NOT IMPLEMENTED")
    print()

    def show_help():
        print()
        print("Partition / GPT:")
        print("  partitions")
        print("      Read + CRC-validate the live GPT and list partitions.")
        print("  gpt")
        print("      Show validated GPT metadata and partition table.")
        print("  partition-info <name>")
        print("      Show exact live-GPT geometry for one partition.")
        print("  dump <partition> [outfile]")
        print("      Stream one GPT partition to disk by name.")
        print("  flash <partition> <image>")
        print("      Exact-size live-GPT guarded write + full SHA256 readback.")
        print()
        print("Bulk backup:")
        print("  dump-firmware <directory>")
        print("      Dump release-oriented firmware + Boot0/Boot1 + preloader.")
        print("  dump-all <directory>")
        print("      Dump all live GPT partitions (including private/userdata),")
        print("      plus Boot0/Boot1. Requires DUMP-ALL confirmation.")
        print()
        print("Hardware areas (read-only):")
        print("  dump-hw boot0 [outfile]")
        print("      Dump Linux mmcblk0boot0 / eMMC BOOT1 selector 1.")
        print("  dump-hw boot1 [outfile]")
        print("      Dump Linux mmcblk0boot1 / eMMC BOOT2 selector 2.")
        print("  dump-preloader [outfile]")
        print("      Parse EMMC_BOOT -> BRLYT -> MMM\\x01 and extract preloader.")
        print()
        print("Advanced/raw read-only:")
        print("  read-raw <addr> <len> <outfile>")
        print("      Stream a 512-byte-aligned eMMC USER range.")
        print("  probe <addr> [len]")
        print("      Legacy small USER-area read + summary.")
        print("  sweep")
        print("      Legacy read-only sample sweep.")
        print()
        print("Compatibility aliases:")
        print("  read <addr> <len> <outfile>")
        print("  write-verify <addr> <partition_size> <image>")
        print()
        print("Session:")
        print("  info")
        print("  help")
        print("  quit")
        print()
        print("Paths containing spaces may be quoted.")

    while True:
        try:
            line = input("t408dl> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            print("Leaving recovery shell.")
            return

        if not line:
            continue

        try:
            parts = shlex.split(line)
        except ValueError as exc:
            print(f"Parse error: {exc}")
            continue
        if not parts:
            continue
        cmd = parts[0].lower()

        try:
            if cmd in ("quit", "exit", "q"):
                print("Leaving recovery shell.")
                return

            if cmd in ("help", "?"):
                show_help()
                continue

            if cmd == "info":
                print()
                print("SoC HW_CODE       = 0x0699")
                print("Storage           = eMMC")
                if isinstance(emmc_info, dict):
                    print(f"block size        = 0x{emmc_info['block_size']:X}")
                    print(f"USER size         = 0x{emmc_info['user']:X}")
                    print(f"Boot0/BOOT1 size  = 0x{emmc_info['boot1']:X}")
                    print(f"Boot1/BOOT2 size  = 0x{emmc_info['boot2']:X}")
                    print(f"RPMB size         = 0x{emmc_info['rpmb']:X}")
                    print(f"eMMC CID          = {emmc_info['cid']}")
                print("USER partition ID = 8")
                print("BOOT1 selector     = 1 (Linux mmcblk0boot0)")
                print("BOOT2 selector     = 2 (Linux mmcblk0boot1)")
                print("READ_DATA          = ENABLED")
                print("WRITE_DATA         = ENABLED (live GPT USER only)")
                print("Boot0/Boot1 write  = DISABLED")
                print("RPMB write         = DISABLED")
                print("FORMAT             = NOT IMPLEMENTED")
                print("ERASE              = NOT IMPLEMENTED")
                continue

            if cmd in ("partitions", "gpt"):
                table = get_live_gpt_table(ep_out, ep_in, emmc_info, verbose=False)
                print()
                print(storage.format_gpt_table(table))
                continue

            if cmd == "partition-info":
                if len(parts) != 2:
                    print("usage: partition-info <name>")
                    continue
                table = get_live_gpt_table(ep_out, ep_in, emmc_info, verbose=False)
                print_partition_info(_partition_or_fail(table, parts[1]))
                continue

            if cmd == "dump":
                if len(parts) not in (2, 3):
                    print("usage: dump <partition> [outfile]")
                    continue
                table = get_live_gpt_table(ep_out, ep_in, emmc_info, verbose=False)
                part = _partition_or_fail(table, parts[1])
                outfile = parts[2] if len(parts) == 3 else f"backups/dumps/{part.name}.bin"
                _, digest, actual = dump_named_partition(
                    ep_out, ep_in, table, part.name, outfile
                )
                print(f"Dumped {part.name} -> {actual}")
                print(f"SHA256 {digest}")
                continue

            if cmd == "flash":
                if len(parts) != 3:
                    print("usage: flash <partition> <image>")
                    continue
                table = get_live_gpt_table(ep_out, ep_in, emmc_info, verbose=False)
                part = _partition_or_fail(table, parts[1])
                write_emmc_range_verify(
                    ep_out, ep_in, part.start, part.size, parts[2]
                )
                continue

            if cmd == "dump-firmware":
                if len(parts) != 2:
                    print("usage: dump-firmware <directory>")
                    continue
                dump_partition_collection(
                    ep_out, ep_in, emmc_info, parts[1], firmware_only=True
                )
                continue

            if cmd == "dump-all":
                if len(parts) != 2:
                    print("usage: dump-all <directory>")
                    continue
                dump_partition_collection(
                    ep_out, ep_in, emmc_info, parts[1], firmware_only=False
                )
                continue

            if cmd == "dump-hw":
                if len(parts) not in (2, 3):
                    print("usage: dump-hw <boot0|boot1> [outfile]")
                    continue
                alias = parts[1]
                default = (
                    "backups/hardware/mmcblk0boot0.bin"
                    if alias.casefold() in ("boot0", "mmcblk0boot0")
                    else "backups/hardware/mmcblk0boot1.bin"
                )
                outfile = parts[2] if len(parts) == 3 else default
                _, digest, actual = dump_hardware_area(
                    ep_out, ep_in, emmc_info, alias, outfile
                )
                print(f"Hardware-area dump -> {actual}")
                print(f"SHA256 {digest}")
                continue

            if cmd == "dump-preloader":
                if len(parts) not in (1, 2):
                    print("usage: dump-preloader [outfile]")
                    continue
                outfile = parts[1] if len(parts) == 2 else "backups/hardware/preloader_raw.img"
                dump_preloader_from_boot0(ep_out, ep_in, emmc_info, outfile)
                continue

            if cmd in ("read-raw", "read"):
                if len(parts) != 4:
                    print("usage: read-raw <addr> <len> <outfile>")
                    continue
                addr = parse_int(parts[1])
                size = parse_int(parts[2])
                _validate_user_read_bounds(addr, size, emmc_info)
                _, digest, actual = read_emmc_area_stream(
                    ep_out,
                    ep_in,
                    addr,
                    size,
                    parts[3],
                    f"raw USER read @ 0x{addr:X}",
                    emmc_part=MTK_DA_EMMC_PART_USER,
                    area_name="USER",
                    collect=False,
                    collision_safe=True,
                )
                print(f"Raw dump -> {actual}")
                print(f"SHA256 {digest}")
                continue

            if cmd == "sweep":
                run_damage_sweep(ep_out, ep_in)
                continue

            if cmd == "probe":
                if len(parts) not in (2, 3):
                    print("usage: probe <addr> [len]")
                    continue
                addr = parse_int(parts[1])
                size = parse_int(parts[2]) if len(parts) == 3 else 0x200
                _validate_user_read_bounds(addr, size, emmc_info)
                # Preserve legacy probe behavior, but make the filename
                # collision-safe so a second handset cannot overwrite the first.
                target = storage.collision_safe_path(
                    Path(f"backups/shell-probe-{addr:016X}-{size:X}.bin")
                )
                data, digest, actual = read_emmc_area_stream(
                    ep_out,
                    ep_in,
                    addr,
                    size,
                    target,
                    f"shell probe @ 0x{addr:X}",
                    emmc_part=MTK_DA_EMMC_PART_USER,
                    area_name="USER",
                    collect=True,
                    collision_safe=False,
                )
                summary = summarize_blob(data)
                print()
                print("[PROBE SUMMARY]")
                print(f"  file          = {actual}")
                print(f"  SHA256        = {digest}")
                print(f"  nonzero bytes = {summary['nonzero']}/{len(data)}")
                first = summary['first_nonzero']
                print(f"  first nonzero = {'NONE' if first is None else f'0x{first:X}'}")
                print(f"  first32       = {data[:32].hex().upper()}")
                continue

            if cmd == "write-verify":
                if len(parts) != 4:
                    print("usage: write-verify <addr> <partition_size> <image>")
                    continue
                addr = parse_int(parts[1])
                part_size = parse_int(parts[2])
                write_emmc_range_verify(ep_out, ep_in, addr, part_size, parts[3])
                continue

            print(f"Unknown command: {cmd}")
            print("Type 'help'.")

        except Exception as exc:
            print()
            print(f"COMMAND FAILED: {exc}")
            print("USB session retained if the DA is still responsive.")
            print()


def main():
    # Recovery-only DA pair:
    #
    # Stage1 contains the updated SHA1 binding for our volatile
    # WRITEPATCHED Stage2. The original Wiko DA remains untouched.
    s3e.DEFAULT_DA = Path(
        "wiko-da/"
        "DA_SWSEC_1836_K510BG_9.0_WIK_FR_31.WRITEPATCHED.bin"
    )

    print("TCL Flip 2 / T408DL Recovery Tool")
    print("MediaTek MT6739 — XFlash eMMC recovery environment")
    print("=" * 72)

    print()
    print("PROVEN RECOVERY CHAIN:")
    print("  - MediaTek Preloader capture and synchronization")
    print("  - volatile S-USBDL bypass")
    print("  - Wiko XFlash DA1 upload and execution")
    print("  - XFlash synchronization")
    print("  - patched XFlash DA2 upload and execution")
    print("  - GET_EMMC_INFO")
    print("  - READ_DATA")
    print("  - GPT-aware WRITE_DATA with full read-back verification")
    print()
    print("SAFETY BOUNDARY:")
    print("  - eMMC USER-area writes only, exact live-GPT partitions")
    print("  - GPT header + entry CRCs validated before named operations")
    print("  - full-partition image size required for writes")
    print("  - streaming reads/writes avoid whole-image RAM buffering")
    print("  - Boot0 / Boot1 reads are enabled; their writes are DISABLED")
    print("  - RPMB writes are DISABLED")
    print("  - FORMAT / ERASE are NOT implemented")

    stage2 = load_stage2()

    stage1_payload = s3e.locate_stage1(
        s3e.DEFAULT_DA
    )

    s3c.verify_stock_image_if_present()

    dev = None

    try:
        print()
        print(
            "[Preloader] Waiting for device..."
        )

        dev = stage1.wait_for_preloader()

        intf, ep_out, ep_in = (
            stage1.setup_usb(
                dev
            )
        )

        stage1.sync_mtk(
            ep_out,
            ep_in,
        )

        hwcode, hwver = (
            stage1.get_hw_code(
                ep_out,
                ep_in,
            )
        )

        print(
            f"  HW_CODE = 0x{hwcode:04X}"
        )

        if hwcode != s3f.EXPECTED_HW_CODE:
            raise RuntimeError(
                f"Unexpected HW_CODE "
                f"0x{hwcode:04X}"
            )

        # --------------------------------------------------------
        # Proven Stage 3C + 3E
        # --------------------------------------------------------

        s3f.establish_stage3e(
            ep_out,
            ep_in,
            stage1_payload,
        )

        # --------------------------------------------------------
        # Proven Stage 3F
        # --------------------------------------------------------

        print()
        print("[DA1] Executing JUMP_DA")

        s3f.jump_da_only(
            ep_out,
            ep_in,
        )

        first = s3g.read_exact(
            ep_in,
            1,
            USB_TIMEOUT_MS,
        )

        print(
            f"  first DA byte = "
            f"0x{first[0]:02X}"
        )

        if first != b"\xC0":
            raise RuntimeError(
                "Expected DA1 C0 marker"
            )

        print(
            "  DA1 C0 marker: PASS"
        )

        # --------------------------------------------------------
        # Proven Stage 3G
        # --------------------------------------------------------

        s3g.perform_xflash_sync(
            ep_out,
            ep_in,
        )

        # --------------------------------------------------------
        # New Stage 3I
        # --------------------------------------------------------

        boot_stage2(
            ep_out,
            ep_in,
            stage2,
        )

        print()
        print("=" * 72)
        print("STORAGE — eMMC IDENTIFICATION")
        print("=" * 72)
        print("  GET_EMMC_INFO only")
        print("  NO READ_DATA")
        print("  NO WRITE_DATA")
        print("  NO FORMAT")

        emmc = devctrl_read(
            ep_out,
            ep_in,
            GET_EMMC_INFO,
            "GET_EMMC_INFO",
        )

        emmc_info = decode_emmc_info(emmc)

        stage2_writeverify_shell(
            ep_out,
            ep_in,
            emmc_info,
        )

        print()
        print("=" * 72)
        print("T408DL XFLASH RECOVERY SHELL CLOSED")
        print("=" * 72)

        print(
            "Wiko XFlash DA2 was uploaded "
            "and executed."
        )

        print(
            "Recovery shell exited; any storage operations above were "
            "explicitly requested in the live session."
        )

        print(
            "Boot0 / Boot1 / RPMB writes remain disabled; "
            "FORMAT / ERASE remain unimplemented."
        )

        return 0

    except KeyboardInterrupt:
        print()
        print("Interrupted.")
        return 130

    except Exception as exc:
        print()
        print("=" * 72)
        print(
            "DA2 BOOT ABORTED / FAILED CLOSED"
        )
        print("=" * 72)
        print(
            f"ERROR: {exc}"
        )

        return 1

    finally:
        if dev is not None:
            print()
            print(
                "Releasing USB session..."
            )

            try:
                stage1.cleanup(
                    dev
                )
            except Exception as exc:
                print(
                    f"Cleanup warning: {exc}"
                )


if __name__ == "__main__":
    sys.exit(main())
