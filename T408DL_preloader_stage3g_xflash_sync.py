#!/usr/bin/env python3
"""
T408DL Stage 3G — XFlash synchronization only.

Reuses proven:
  Stage 3C  S-USBDL -> 0
  Stage 3E  Wiko DA Stage-1 SEND_DA
  Stage 3F  JUMP_DA

Then performs only the standard XFlash startup synchronization:
  C0 observed
  SYNC_SIGNAL
  SETUP_ENVIRONMENT + parameter
  SETUP_HW_INIT_PARAMS + parameter
  final SYNC_SIGNAL response

NO storage-info queries.
NO GET_EMMC_INFO.
NO READ_DATA.
NO WRITE_DATA.
NO flash operations.
"""

from __future__ import annotations

import struct
import sys

import T408DL_preloader_catcher as stage1
import T408DL_preloader_stage3c_susbdl_zero as s3c
import T408DL_preloader_stage3e_wiko_stage1 as s3e
import T408DL_preloader_stage3f_jump_wiko as s3f


MAGIC = 0xFEEEEEEF
DT_PROTOCOL_FLOW = 1

SYNC_SIGNAL = 0x434E5953
SETUP_ENVIRONMENT = 0x010100
SETUP_HW_INIT_PARAMS = 0x010101

USB_TIMEOUT_MS = 5000


def write_exact(ep_out, data, timeout=USB_TIMEOUT_MS):
    data = bytes(data)
    n = ep_out.write(data, timeout)

    if int(n) != len(data):
        raise RuntimeError(
            f"Short USB write: {n}/{len(data)}"
        )


def read_exact(ep_in, length, timeout=USB_TIMEOUT_MS):
    return s3c.read_exact(
        ep_in,
        length,
        timeout,
    )


def xsend(ep_out, payload):
    """
    Send one XFlash protocol-flow packet.
    """
    if isinstance(payload, int):
        payload = struct.pack("<I", payload)
    else:
        payload = bytes(payload)

    hdr = struct.pack(
        "<III",
        MAGIC,
        DT_PROTOCOL_FLOW,
        len(payload),
    )

    print(
        f"  TX hdr: magic=0x{MAGIC:08X} "
        f"type={DT_PROTOCOL_FLOW} len=0x{len(payload):X}"
    )
    print(f"  TX payload: {payload.hex().upper()}")

    write_exact(ep_out, hdr)
    write_exact(ep_out, payload)


def xread_packet(ep_in):
    hdr = read_exact(
        ep_in,
        12,
        USB_TIMEOUT_MS,
    )

    magic, dtype, length = struct.unpack(
        "<III",
        hdr,
    )

    print(
        f"  RX hdr: magic=0x{magic:08X} "
        f"type={dtype} len=0x{length:X}"
    )

    if magic != MAGIC:
        raise RuntimeError(
            f"Bad XFlash magic 0x{magic:08X}"
        )

    if length > 0x10000:
        raise RuntimeError(
            f"Suspicious XFlash packet length 0x{length:X}"
        )

    payload = read_exact(
        ep_in,
        length,
        USB_TIMEOUT_MS,
    )

    print(
        f"  RX payload: {payload.hex().upper()}"
    )

    return dtype, payload


def read_status(ep_in):
    dtype, payload = xread_packet(ep_in)

    if len(payload) == 2:
        status = struct.unpack("<H", payload)[0]

    elif len(payload) == 4:
        status = struct.unpack("<I", payload)[0]

        # MTKClient treats this magic value as success too.
        if status == MAGIC:
            status = 0

    else:
        raise RuntimeError(
            f"Unexpected status payload length {len(payload)}"
        )

    print(f"  decoded status = 0x{status:08X}")

    return status


def send_param(ep_out, ep_in, payload):
    payload = bytes(payload)

    print()
    print(
        f"[XFlash parameter] {len(payload)} bytes"
    )

    xsend(
        ep_out,
        payload,
    )

    status = read_status(
        ep_in,
    )

    if status != 0:
        raise RuntimeError(
            f"Parameter rejected: 0x{status:08X}"
        )

    print("  parameter status: PASS")


def perform_xflash_sync(ep_out, ep_in):
    print()
    print("=" * 72)
    print("XFLASH — SYNCHRONIZATION")
    print("=" * 72)

    # ------------------------------------------------------------
    # 1. SYNC_SIGNAL
    #
    # MTKClient xsend(SYNC_SIGNAL) does not immediately read a status.
    # ------------------------------------------------------------

    print()
    print("[1] SYNC_SIGNAL")
    print(f"  command = 0x{SYNC_SIGNAL:08X}")

    xsend(
        ep_out,
        SYNC_SIGNAL,
    )

    # ------------------------------------------------------------
    # 2. SETUP_ENVIRONMENT
    # ------------------------------------------------------------

    print()
    print("[2] SETUP_ENVIRONMENT")
    print(f"  command = 0x{SETUP_ENVIRONMENT:08X}")

    xsend(
        ep_out,
        SETUP_ENVIRONMENT,
    )

    # Current MTKClient defaults:
    #
    # da_log_level = 2
    # log_channel  = 1 (UART)
    # system_os    = 1 (Linux)
    # ufs_provision= 0
    # reserved     = 0
    env = struct.pack(
        "<IIIII",
        2,
        1,
        1,
        0,
        0,
    )

    print(
        "  env = "
        "loglevel=2, channel=UART(1), "
        "OS=Linux(1), UFS=0, reserved=0"
    )

    send_param(
        ep_out,
        ep_in,
        env,
    )

    # ------------------------------------------------------------
    # 3. SETUP_HW_INIT_PARAMS
    # ------------------------------------------------------------

    print()
    print("[3] SETUP_HW_INIT_PARAMS")
    print(
        f"  command = "
        f"0x{SETUP_HW_INIT_PARAMS:08X}"
    )

    xsend(
        ep_out,
        SETUP_HW_INIT_PARAMS,
    )

    send_param(
        ep_out,
        ep_in,
        struct.pack("<I", 0),
    )

    # ------------------------------------------------------------
    # 4. Final DA sync indication
    # ------------------------------------------------------------

    print()
    print("[4] Waiting for final DA sync packet")

    dtype, payload = xread_packet(
        ep_in,
    )

    if len(payload) != 4:
        raise RuntimeError(
            f"Expected 4-byte final sync payload, "
            f"got {len(payload)}"
        )

    value = struct.unpack(
        "<I",
        payload,
    )[0]

    print(
        f"  final value = "
        f"0x{value:08X}"
    )

    if value != SYNC_SIGNAL:
        raise RuntimeError(
            f"Unexpected final sync value "
            f"0x{value:08X}"
        )

    print()
    print("  XFlash final SYNC_SIGNAL: PASS")
    print("  XFLASH PROTOCOL SYNCHRONIZATION: PROVEN")


def main():
    print(
        "TCL Flip 2 / T408DL XFlash Synchronization Test"
    )
    print(
        "Synchronize Wiko XFlash DA1"
    )
    print("=" * 72)

    print()
    print("BOUNDARY:")
    print("  - apply proven volatile S-USBDL bypass")
    print("  - upload accepted Wiko XFlash DA1")
    print("  - execute DA1 through JUMP_DA")
    print("  - complete XFlash startup sync")
    print("  - NO GET_EMMC_INFO")
    print("  - NO storage enumeration")
    print("  - NO READ_DATA")
    print("  - NO WRITE_DATA")
    print("  - NO flash writes")

    payload = s3e.locate_stage1(
        s3e.DEFAULT_DA
    )

    s3c.verify_stock_image_if_present()

    dev = None

    try:
        print()
        print("[Preloader] Waiting for device...")

        dev = stage1.wait_for_preloader()

        intf, ep_out, ep_in = (
            stage1.setup_usb(dev)
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

        # Proven Stage3C + Stage3E setup.
        s3f.establish_stage3e(
            ep_out,
            ep_in,
            payload,
        )

        print()
        print("[DA1] JUMP_DA")

        s3f.jump_da_only(
            ep_out,
            ep_in,
        )

        # We intentionally reproduce the exact proven 3F observation,
        # but this time retain the session and proceed with XFlash sync.
        print()
        print("[DA1] Waiting for C0")

        first = read_exact(
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
                "Expected XFlash C0 byte"
            )

        print("  C0 sync marker: PASS")

        perform_xflash_sync(
            ep_out,
            ep_in,
        )

        print()
        print("=" * 72)
        print("XFLASH SYNCHRONIZATION SUCCESS")
        print("=" * 72)
        print(
            "Wiko XFlash DA1 synchronized successfully."
        )
        print(
            "Final DA response contained SYNC_SIGNAL."
        )
        print(
            "No storage-info command was sent."
        )
        print(
            "No flash read/write command was sent."
        )

        return 0

    except KeyboardInterrupt:
        print()
        print("Interrupted.")
        return 130

    except Exception as exc:
        print()
        print("=" * 72)
        print("XFLASH SYNCHRONIZATION ABORTED / FAILED CLOSED")
        print("=" * 72)
        print(f"ERROR: {exc}")
        print()
        print(
            "Do not infer full XFlash synchronization "
            "unless the final returned value is exactly "
            "0x434E5953."
        )

        return 1

    finally:
        if dev is not None:
            print()
            print("Releasing USB session...")

            try:
                stage1.cleanup(dev)
            except Exception as exc:
                print(
                    f"Cleanup warning: {exc}"
                )


if __name__ == "__main__":
    sys.exit(main())
