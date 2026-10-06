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

STAGE2_PATH = Path(
    "wiko-da/WIKO_MT6739_STAGE2.bin"
)

STAGE2_ADDR = 0x40000000
STAGE2_LEN = 0x3A49C

STAGE2_SHA256 = (
    "876b69d3e358d3abec21a5db670fad3e"
    "3c1cf9909e0c697eb9b4ae5eeb779508"
)


def load_stage2():
    data = STAGE2_PATH.read_bytes()

    print()
    print("[Stage2 verification]")
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
    print("[Stage2 data packet]")
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
            "Stage2 data was rejected: "
            f"0x{status:08X}"
        )

    print(
        "  Stage2 upload acceptance: PASS"
    )


def boot_stage2(ep_out, ep_in, stage2):
    print()
    print("=" * 72)
    print("STAGE 3I — BOOT WIKO XFLASH STAGE 2")
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
    print("[3] Sending unsigned Stage2 image")

    send_stage2_data(
        ep_out,
        ep_in,
        stage2,
    )

    # ------------------------------------------------------------
    # Stage2 execution result
    # ------------------------------------------------------------

    print()
    print("[4] Waiting for Stage2 execution result")

    time.sleep(0.5)

    try:
        final = s3g.read_status(
            ep_in,
        )
    except Exception as exc:
        raise RuntimeError(
            "No valid post-BOOT_TO Stage2 status "
            f"received: {exc}"
        )

    print(
        f"  execution status = "
        f"0x{final:08X}"
    )

    if final == 0:
        print(
            "  Stage2 execution response: "
            "SUCCESS (0x00000000)"
        )

    elif final == s3g.SYNC_SIGNAL:
        print(
            "  Stage2 execution response: "
            "SYNC_SIGNAL"
        )

    else:
        raise RuntimeError(
            f"Unexpected Stage2 execution status "
            f"0x{final:08X}"
        )

    print()
    print(
        "  WIKO XFLASH STAGE 2 EXECUTION: PROVEN"
    )


def main():
    print(
        "T408DL_preloader_stage3i_boot_stage2.py"
    )

    print(
        "Controlled Wiko XFlash Stage-2 boot"
    )

    print("=" * 72)

    print()
    print("BOUNDARY:")
    print("  - reproduce proven Stage 3C")
    print("  - reproduce proven Stage 3E")
    print("  - reproduce proven Stage 3F")
    print("  - reproduce proven Stage 3G")
    print("  - upload Stage2 to 0x40000000")
    print("  - execute Stage2")
    print("  - observe execution status ONLY")
    print("  - NO GET_EMMC_INFO")
    print("  - NO READ_DATA")
    print("  - NO WRITE_DATA")
    print("  - NO FORMAT")
    print("  - NO storage operation")

    stage2 = load_stage2()

    stage1_payload = s3e.locate_stage1(
        s3e.DEFAULT_DA
    )

    s3c.verify_stock_image_if_present()

    dev = None

    try:
        print()
        print(
            "[Stage 1] Waiting for Preloader..."
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
        print("[Stage 3F] JUMP_DA")

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
                "Expected Stage1 C0 marker"
            )

        print(
            "  Stage1 C0 marker: PASS"
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
        print("STAGE 3I SUCCESS")
        print("=" * 72)

        print(
            "Wiko XFlash Stage 2 was uploaded "
            "and executed."
        )

        print(
            "No storage-information command "
            "was sent."
        )

        print(
            "No flash read/write operation "
            "was attempted."
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
            "STAGE 3I ABORTED / FAILED CLOSED"
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
