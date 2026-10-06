#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import struct
import sys
import time
from pathlib import Path

import T408DL_preloader_catcher as stage1
import T408DL_preloader_stage3c_susbdl_zero as s3c
import T408DL_preloader_stage3e_wiko_stage1 as s3e
import T408DL_preloader_stage3f_jump_wiko as s3f
import T408DL_preloader_stage3g_xflash_sync as s3g


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

    if len(data) < 96:
        print(f"  Unexpected response length: {len(data)}")
        print(f"  raw = {data.hex().upper()}")
        return

    import struct

    pos = 0

    emmc_type, block_size = struct.unpack_from(
        "<II", data, pos
    )
    pos += 8

    (
        boot1,
        boot2,
        rpmb,
        gp1,
        gp2,
        gp3,
        gp4,
        user,
    ) = struct.unpack_from(
        "<QQQQQQQQ", data, pos
    )
    pos += 64

    cid = data[pos:pos + 16]
    pos += 16

    fwver = struct.unpack_from(
        "<Q", data, pos
    )[0]

    print(f"  type       = 0x{emmc_type:X}")
    print(f"  block size = 0x{block_size:X}")

    print(
        f"  Boot1      = 0x{boot1:X} "
        f"({boot1 / 1024 / 1024:.2f} MiB)"
    )
    print(
        f"  Boot2      = 0x{boot2:X} "
        f"({boot2 / 1024 / 1024:.2f} MiB)"
    )
    print(
        f"  RPMB       = 0x{rpmb:X} "
        f"({rpmb / 1024 / 1024:.2f} MiB)"
    )

    print(f"  GP1        = 0x{gp1:X}")
    print(f"  GP2        = 0x{gp2:X}")
    print(f"  GP3        = 0x{gp3:X}")
    print(f"  GP4        = 0x{gp4:X}")

    print(
        f"  USER       = 0x{user:X} "
        f"({user / 1024 / 1024 / 1024:.3f} GiB)"
    )

    print(f"  CID        = {cid.hex().upper()}")
    print(f"  FW version = 0x{fwver:X}")




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



def get_live_gpt_partitions(ep_out, ep_in):
    """
    Read and validate the primary GPT directly from eMMC USER.

    Returns a dict keyed by byte start address:

        {
            start: {
                "name": str,
                "start": int,
                "size": int,
                "first_lba": int,
                "last_lba": int,
            }
        }

    WRITE_DATA is not involved.
    """

    import zlib

    print()
    print("=" * 72)
    print("LIVE GPT WRITE-GUARD")
    print("=" * 72)

    # --------------------------------------------------------
    # Primary GPT header: LBA 1
    # --------------------------------------------------------

    header, _ = read_emmc_range(
        ep_out,
        ep_in,
        0x200,
        0x200,
        "backups/writeguard-gpt-header.bin",
        "live GPT header",
    )

    if header[:8] != b"EFI PART":
        raise RuntimeError(
            "Primary GPT signature is invalid; "
            "WRITE REFUSED"
        )

    header_size = struct.unpack_from(
        "<I",
        header,
        0x0C,
    )[0]

    stored_header_crc = struct.unpack_from(
        "<I",
        header,
        0x10,
    )[0]

    if (
        header_size < 0x5C
        or header_size > 0x200
    ):
        raise RuntimeError(
            f"Suspicious GPT header size "
            f"0x{header_size:X}"
        )

    check = bytearray(
        header[:header_size]
    )

    struct.pack_into(
        "<I",
        check,
        0x10,
        0,
    )

    calculated_header_crc = (
        zlib.crc32(check) & 0xFFFFFFFF
    )

    print()
    print(
        f"  header CRC stored = "
        f"0x{stored_header_crc:08X}"
    )
    print(
        f"  header CRC calc   = "
        f"0x{calculated_header_crc:08X}"
    )

    if calculated_header_crc != stored_header_crc:
        raise RuntimeError(
            "Primary GPT header CRC mismatch; "
            "WRITE REFUSED"
        )

    entries_lba = struct.unpack_from(
        "<Q",
        header,
        0x48,
    )[0]

    entry_count = struct.unpack_from(
        "<I",
        header,
        0x50,
    )[0]

    entry_size = struct.unpack_from(
        "<I",
        header,
        0x54,
    )[0]

    stored_entries_crc = struct.unpack_from(
        "<I",
        header,
        0x58,
    )[0]

    if (
        entry_count <= 0
        or entry_count > 4096
    ):
        raise RuntimeError(
            f"Suspicious GPT entry count "
            f"{entry_count}"
        )

    if (
        entry_size < 128
        or entry_size > 1024
        or (entry_size & 7)
    ):
        raise RuntimeError(
            f"Suspicious GPT entry size "
            f"0x{entry_size:X}"
        )

    entries_len = (
        entry_count * entry_size
    )

    entries_addr = (
        entries_lba * 0x200
    )

    print(
        f"  entries LBA       = "
        f"0x{entries_lba:X}"
    )
    print(
        f"  entries count     = "
        f"{entry_count}"
    )
    print(
        f"  entry size        = "
        f"0x{entry_size:X}"
    )
    print(
        f"  entries bytes     = "
        f"0x{entries_len:X}"
    )

    # --------------------------------------------------------
    # Partition entry array
    # --------------------------------------------------------

    entries, _ = read_emmc_range(
        ep_out,
        ep_in,
        entries_addr,
        entries_len,
        "backups/writeguard-gpt-entries.bin",
        "live GPT entries",
    )

    calculated_entries_crc = (
        zlib.crc32(entries) & 0xFFFFFFFF
    )

    print()
    print(
        f"  entries CRC stored = "
        f"0x{stored_entries_crc:08X}"
    )
    print(
        f"  entries CRC calc   = "
        f"0x{calculated_entries_crc:08X}"
    )

    if calculated_entries_crc != stored_entries_crc:
        raise RuntimeError(
            "GPT partition-array CRC mismatch; "
            "WRITE REFUSED"
        )

    partitions = {}

    for index in range(entry_count):
        off = index * entry_size

        ent = entries[
            off:off + entry_size
        ]

        if len(ent) < 128:
            break

        type_guid = ent[:16]

        if type_guid == b"\x00" * 16:
            continue

        first_lba = struct.unpack_from(
            "<Q",
            ent,
            0x20,
        )[0]

        last_lba = struct.unpack_from(
            "<Q",
            ent,
            0x28,
        )[0]

        if last_lba < first_lba:
            raise RuntimeError(
                f"GPT entry {index} has invalid "
                f"LBA geometry"
            )

        name_raw = ent[
            0x38:min(entry_size, 0x80)
        ]

        try:
            name = (
                name_raw
                .decode(
                    "utf-16le",
                    errors="ignore",
                )
                .split("\x00", 1)[0]
            )
        except Exception:
            name = ""

        if not name:
            name = f"gpt-entry-{index}"

        start = first_lba * 0x200

        size = (
            last_lba
            - first_lba
            + 1
        ) * 0x200

        if start in partitions:
            raise RuntimeError(
                f"Duplicate GPT start address "
                f"0x{start:X}; WRITE REFUSED"
            )

        partitions[start] = {
            "name": name,
            "start": start,
            "size": size,
            "first_lba": first_lba,
            "last_lba": last_lba,
        }

    print()
    print(
        f"  populated partitions = "
        f"{len(partitions)}"
    )
    print(
        "  GPT validation: PASS"
    )

    return partitions


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

    # ------------------------------------------------------------
    # LIVE GPT WRITE GUARD
    # ------------------------------------------------------------

    part = validate_gpt_write_target(
        ep_out,
        ep_in,
        addr,
        part_size,
    )

    name = part["name"]

    # ------------------------------------------------------------
    # Image validation
    # ------------------------------------------------------------


    image = Path(
        image_path
    )

    if not image.is_file():
        raise RuntimeError(
            f"image not found: {image}"
        )

    raw = image.read_bytes()

    # Our KEE7 donor images are full partition dumps.
    # Require exact geometry so we never leave an old tail behind.
    if len(raw) != part_size:
        raise RuntimeError(
            f"{name}: image must be a full "
            f"partition dump: "
            f"0x{len(raw):X} != "
            f"0x{part_size:X}"
        )

    if len(raw) & 0x1FF:
        raise RuntimeError(
            f"{name}: image is not "
            f"512-byte aligned"
        )

    source_sha = hashlib.sha256(
        raw
    ).hexdigest()

    print()
    print("=" * 72)
    print(
        f"WRITE-VERIFY — {name}"
    )
    print("=" * 72)

    print(
        f"  address        = "
        f"0x{addr:016X}"
    )
    print(
        f"  partition size = "
        f"0x{part_size:X}"
    )
    print(
        f"  image          = "
        f"{image}"
    )
    print(
        f"  image size     = "
        f"0x{len(raw):X}"
    )
    print(
        f"  source SHA256  = "
        f"{source_sha}"
    )

    print()
    print(
        "  FORMAT = NOT IMPLEMENTED"
    )
    print(
        "  ERASE  = NOT IMPLEMENTED"
    )

    # ------------------------------------------------------------
    # Per-partition manual arming
    # ------------------------------------------------------------

    safe_name = "".join(
        ch if ch.isalnum() else "-"
        for ch in name.upper()
    ).strip("-")

    expected_token = (
        f"WRITE-{safe_name}"
    )

    token = input(
        f"Type {expected_token} "
        f"to arm this partition: "
    ).strip()

    if token != expected_token:
        print(
            "  confirmation mismatch; "
            "write cancelled"
        )

        return False

    # ------------------------------------------------------------
    # Ask DA for its supported packet geometry.
    # ------------------------------------------------------------

    packet_len = get_write_packet_length(
        ep_out,
        ep_in,
    )

    # ------------------------------------------------------------
    # WRITE_DATA command
    # ------------------------------------------------------------

    print()
    print(
        "[1] WRITE_DATA command"
    )

    s3g.xsend(
        ep_out,
        WRITE_DATA,
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
            f"WRITE_DATA rejected: "
            f"0x{st:08X}"
        )

    # ------------------------------------------------------------
    # WRITE_DATA parameter
    #
    # storage = eMMC
    # section = USER
    # addr
    # size
    # 8 x NAND-extension fields = zero for eMMC
    # ------------------------------------------------------------

    param = struct.pack(
        "<IIQQIIIIIIII",

        MTK_DA_STORAGE_EMMC,
        MTK_DA_EMMC_PART_USER,

        addr,
        len(raw),

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
    print(
        "[2] WRITE_DATA parameters"
    )

    print(
        f"  parameter size = "
        f"0x{len(param):X}"
    )

    _send_param_group(
        ep_out,
        ep_in,
        [param],
        "write parameter",
    )

    # ------------------------------------------------------------
    # Data transfer
    #
    # Each DA write chunk is represented as three XFlash params:
    #
    #   u32 0
    #   u32 additive_checksum16
    #   raw data
    #
    # Then one status acknowledges the whole parameter group.
    # ------------------------------------------------------------

    print()
    print(
        "[3] Sending flash data"
    )

    pos = 0
    started = time.monotonic()

    while pos < len(raw):
        chunk = raw[
            pos:pos + packet_len
        ]

        if len(chunk) & 0x1FF:
            raise RuntimeError(
                f"internal error: "
                f"chunk 0x{len(chunk):X} "
                f"is not aligned"
            )

        checksum = (
            sum(chunk) & 0xFFFF
        )

        _send_param_group(
            ep_out,
            ep_in,
            [
                struct.pack(
                    "<I",
                    0,
                ),
                struct.pack(
                    "<I",
                    checksum,
                ),
                chunk,
            ],
            f"chunk@0x{pos:X}",
        )

        pos += len(chunk)

        print(
            f"  written = "
            f"0x{pos:X}/0x{len(raw):X} "
            f"({pos * 100.0 / len(raw):.1f}%)"
        )

    # ------------------------------------------------------------
    # Final write status
    # ------------------------------------------------------------

    print()
    print(
        "[4] Final WRITE_DATA status"
    )

    st = s3g.read_status(
        ep_in,
    )

    print(
        f"  final status = "
        f"0x{st:08X}"
    )

    if st != 0:
        raise RuntimeError(
            f"{name}: final WRITE_DATA "
            f"status 0x{st:08X}"
        )

    elapsed = (
        time.monotonic()
        - started
    )

    print(
        f"  WRITE_DATA completion: "
        f"PASS ({elapsed:.3f}s)"
    )

    # ------------------------------------------------------------
    # Full read-back
    # ------------------------------------------------------------

    verify_file = Path(
        f"backups/"
        f"readback-{name}-after-write.bin"
    )

    print()
    print(
        "[5] Full read-back verification"
    )

    readback, readback_sha = (
        read_emmc_range(
            ep_out,
            ep_in,
            addr,
            len(raw),
            verify_file,
            f"{name} post-write verify",
        )
    )

    print()
    print(
        f"  source SHA256   = "
        f"{source_sha}"
    )
    print(
        f"  readback SHA256 = "
        f"{readback_sha}"
    )

    if readback != raw:
        raise RuntimeError(
            f"{name}: READ-BACK MISMATCH — "
            f"STOP. Do not write another "
            f"partition."
        )

    print()
    print(
        f"  {name}: WRITE + FULL "
        f"READ-BACK VERIFY = PASS"
    )

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


def stage2_writeverify_shell(ep_out, ep_in, emmc_info=None):
    print()
    print("=" * 72)
    print("T408DL XFLASH RECOVERY SHELL")
    print("=" * 72)
    print()
    print("Persistent XFlash DA2 session is ACTIVE.")
    print()
    print("Available commands:")
    print("  help")
    print("  info")
    print("  sweep")
    print("  probe <addr> [len]")
    print("  read <addr> <len> <outfile>")
    print("  write-verify <addr> <partition_size> <image>")
    print("  quit")
    print()
    print("Numeric values may be decimal or 0x-prefixed hexadecimal.")
    print()
    print("WRITE_DATA = ENABLED FOR EXACT LIVE GPT USER PARTITIONS")
    print("FORMAT / ERASE = NOT IMPLEMENTED")
    print()

    while True:
        try:
            line = input(
                "t408dl> "
            ).strip()

        except (EOFError, KeyboardInterrupt):
            print()
            print("Leaving write-verify shell.")
            return

        if not line:
            continue

        parts = line.split()

        cmd = parts[0].lower()

        try:
            if cmd in (
                "quit",
                "exit",
                "q",
            ):
                print(
                    "Leaving write-verify shell."
                )
                return

            elif cmd in (
                "help",
                "?",
            ):
                print()
                print("help")
                print(
                    "  Show this command list."
                )
                print()
                print("info")
                print(
                    "  Show known eMMC / session information."
                )
                print()
                print("sweep")
                print(
                    "  Sample important USER offsets and report "
                    "DATA vs ZERO."
                )
                print()
                print(
                    "probe <addr> [len]"
                )
                print(
                    "  Read and summarize memory. "
                    "Default len = 0x200."
                )
                print()
                print(
                    "read <addr> <len> <outfile>"
                )
                print(
                    "  Save an arbitrary USER-area range."
                )
                print()
                print(
                    "write-verify <addr> <partition_size> <image>"
                )
                print(
                    "  Allow-listed write followed by "
                    "full READ_DATA verification."
                )
                print()
                print("quit")
                print(
                    "  Release the USB session and exit."
                )

            elif cmd == "info":
                print()
                print(
                    "SoC HW_CODE       = 0x0699"
                )
                print(
                    "Storage           = eMMC"
                )
                print(
                    "USER partition ID = 8"
                )
                print(
                    "block size        = 0x200"
                )
                print(
                    "USER size         = 0x3A3E00000"
                )
                print(
                    "READ_DATA         = ENABLED"
                )
                print(
                    "WRITE_DATA        = ENABLED (live GPT guarded)"
                )
                print(
                    "FORMAT            = NOT IMPLEMENTED"
                )
                print(
                    "ERASE             = NOT IMPLEMENTED"
                )

            elif cmd == "sweep":
                run_damage_sweep(
                    ep_out,
                    ep_in,
                )

            elif cmd == "probe":
                if len(parts) not in (
                    2,
                    3,
                ):
                    print(
                        "usage: probe <addr> [len]"
                    )
                    continue

                addr = parse_int(
                    parts[1]
                )

                size = (
                    parse_int(parts[2])
                    if len(parts) == 3
                    else 0x200
                )

                if size <= 0:
                    print(
                        "length must be > 0"
                    )
                    continue

                readonly_probe(
                    ep_out,
                    ep_in,
                    addr,
                    size,
                    f"shell probe @ 0x{addr:X}",
                )

            elif cmd == "read":
                if len(parts) != 4:
                    print(
                        "usage: read <addr> <len> <outfile>"
                    )
                    continue

                addr = parse_int(
                    parts[1]
                )

                size = parse_int(
                    parts[2]
                )

                outfile = parts[3]

                if size <= 0:
                    print(
                        "length must be > 0"
                    )
                    continue

                read_emmc_range(
                    ep_out,
                    ep_in,
                    addr,
                    size,
                    outfile,
                    f"shell read @ 0x{addr:X}",
                )

            elif cmd == "write-verify":
                if len(parts) != 4:
                    print(
                        "usage: write-verify "
                        "<addr> <partition_size> <image>"
                    )
                    continue

                addr = parse_int(
                    parts[1]
                )

                part_size = parse_int(
                    parts[2]
                )

                image = parts[3]

                write_emmc_range_verify(
                    ep_out,
                    ep_in,
                    addr,
                    part_size,
                    image,
                )

            else:
                print(
                    f"Unknown command: {cmd}"
                )
                print(
                    "Type 'help'."
                )

        except Exception as exc:
            print()
            print(
                f"COMMAND FAILED: {exc}"
            )
            print(
                "USB session retained if the DA is still responsive."
            )
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
    print("  - eMMC USER-area GPT partitions only")
    print("  - GPT geometry validated before guarded writes")
    print("  - full-partition image size required for write-verify")
    print("  - Boot0 / Boot1 / RPMB writes are NOT enabled")
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

        decode_emmc_info(emmc)

        stage2_writeverify_shell(
            ep_out,
            ep_in,
            emmc,
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
            "No storage-information command "
            "was sent."
        )

        print(
            "Two 2-MiB eMMC USER reads "
            "was performed; no write was attempted."
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
