#!/usr/bin/env python3
"""
T408DL Stage 3F — controlled JUMP_DA proof.

Reproduces the proven chain:

    Stage 1 capture
    WDT disable
    Stage 3C S-USBDL -> 0
    independent verification
    Stage 3E-B real Wiko xflash Stage-1 SEND_DA
    JUMP_DA to 0x00200000

After JUMP_DA, this script performs exactly ONE DA-side observation:
it waits for the first byte and expects the standard XFlash sync byte 0xC0.

It then STOPS.

NO XFlash synchronization commands.
NO DA commands.
NO eMMC commands.
NO storage reads.
NO storage writes.
NO flash operations.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import usb.core

import T408DL_preloader_catcher as stage1
import T408DL_preloader_stage3c_susbdl_zero as s3c
import T408DL_preloader_stage3e_wiko_stage1 as s3e


EXPECTED_HW_CODE = 0x0699

CMD_JUMP_DA = 0xD5

# Proven/observed Wiko XFlash Stage-1 load address.
DA_ENTRY = 0x00200000

# Standard XFlash Stage-1 first synchronization byte.
EXPECTED_DA_SYNC = 0xC0

USB_TIMEOUT_MS = 5000
DA_FIRST_BYTE_TIMEOUT_MS = 5000


def write_exact(ep_out, data, timeout=USB_TIMEOUT_MS):
    data = bytes(data)

    n = ep_out.write(
        data,
        timeout,
    )

    if int(n) != len(data):
        raise RuntimeError(
            f"short USB write: {n}/{len(data)}"
        )


def jump_da_only(ep_out, ep_in):
    """
    Issue only the legacy MTK JUMP_DA transaction.

    Expected generic framing:

        D5          -> D5
        address     -> address
                     -> 16-bit status

    After status==0, execution transfers to Stage 1.
    """

    print()
    print("=" * 72)
    print("STAGE 3F — JUMP_DA")
    print("=" * 72)

    print(f"  entry address = 0x{DA_ENTRY:08X}")
    print("  post-jump TX  = NONE")
    print("  DA commands   = NONE")
    print()

    # ------------------------------------------------------------
    # Opcode
    # ------------------------------------------------------------

    write_exact(
        ep_out,
        bytes([CMD_JUMP_DA]),
    )

    cmd_reply = s3c.read_exact(
        ep_in,
        1,
        USB_TIMEOUT_MS,
    )

    print("[JUMP_DA header]")
    print(
        f"  opcode RX     = "
        f"{cmd_reply.hex().upper()}"
    )

    if cmd_reply != bytes([CMD_JUMP_DA]):
        raise RuntimeError(
            "JUMP_DA opcode echo mismatch"
        )

    # ------------------------------------------------------------
    # Entry address
    # ------------------------------------------------------------

    addr_raw = DA_ENTRY.to_bytes(
        4,
        "big",
    )

    print(
        f"  address TX    = "
        f"{addr_raw.hex().upper()}"
    )

    write_exact(
        ep_out,
        addr_raw,
    )

    addr_reply = s3c.read_exact(
        ep_in,
        4,
        USB_TIMEOUT_MS,
    )

    print(
        f"  address RX    = "
        f"{addr_reply.hex().upper()}"
    )

    # Unlike SEND_DA, do NOT tolerate undocumented alternate framing.
    # Fail closed unless JUMP_DA explicitly confirms the requested PC.
    if addr_reply != addr_raw:
        raise RuntimeError(
            "JUMP_DA address response mismatch; "
            "refusing to assume control transfer"
        )

    # ------------------------------------------------------------
    # Final Preloader status
    # ------------------------------------------------------------

    status = s3c.rword(
        ep_in,
    )

    print(
        f"  status        = "
        f"0x{status:04X}"
    )

    if status != 0x0000:
        raise RuntimeError(
            f"JUMP_DA rejected with status "
            f"0x{status:04X}"
        )

    print()
    print("  JUMP_DA transaction: PASS")
    print("  Preloader accepted execution transfer.")

    return status


def observe_first_da_byte(ep_in):
    """
    Observe only the first byte emitted by the executed DA.

    Do NOT reply to it.
    """

    print()
    print("[DA execution observation]")
    print(
        f"  waiting up to "
        f"{DA_FIRST_BYTE_TIMEOUT_MS} ms "
        f"for first DA byte..."
    )

    started = time.monotonic()

    try:
        raw = bytes(
            ep_in.read(
                1,
                DA_FIRST_BYTE_TIMEOUT_MS,
            )
        )

    except usb.core.USBTimeoutError:
        elapsed = time.monotonic() - started

        raise RuntimeError(
            "No DA byte received after JUMP_DA "
            f"({elapsed:.3f}s timeout)"
        )

    elapsed = time.monotonic() - started

    if len(raw) != 1:
        raise RuntimeError(
            f"Expected exactly one DA byte, "
            f"received {len(raw)}"
        )

    value = raw[0]

    print(
        f"  first byte = "
        f"0x{value:02X}"
    )
    print(
        f"  elapsed    = "
        f"{elapsed:.3f}s"
    )

    if value != EXPECTED_DA_SYNC:
        raise RuntimeError(
            f"Unexpected first DA byte "
            f"0x{value:02X}; expected "
            f"0x{EXPECTED_DA_SYNC:02X}"
        )

    print()
    print("  XFlash Stage-1 sync byte 0xC0: PASS")
    print("  DA CODE EXECUTION: PROVEN")

    return value


def establish_stage3e(ep_out, ep_in, payload):
    """
    Reproduce only already-proven state transitions.
    """

    # ------------------------------------------------------------
    # Watchdog
    # ------------------------------------------------------------

    s3c.disable_watchdog(
        ep_out,
        ep_in,
    )

    snapshot_end = (
        s3c.G_DA_VERIFIED + 2
    ) & ~1

    # ------------------------------------------------------------
    # Initial live state
    # ------------------------------------------------------------

    wire, low, initial, final = (
        s3c.wrapped_d0_snapshot(
            ep_out,
            ep_in,
            snapshot_end,
        )
    )

    if initial != 0 or final != 0:
        raise RuntimeError(
            "Initial wrapped D0 failed"
        )

    replay = (
        s3c.build_stage3c_replay(
            wire,
            low,
        )
    )

    # ------------------------------------------------------------
    # Proven Stage 3C zero-store
    # ------------------------------------------------------------

    print()
    print(
        "[Stage 3C] Applying proven "
        "volatile S-USBDL zero-store..."
    )

    s3c.d3_write_replay(
        ep_out,
        ep_in,
        replay,
    )

    s3c.verify_hw_code(
        ep_out,
        ep_in,
    )

    # ------------------------------------------------------------
    # Independent state verification
    # ------------------------------------------------------------

    _, low2, initial, final = (
        s3c.wrapped_d0_snapshot(
            ep_out,
            ep_in,
            snapshot_end,
        )
    )

    if initial != 0 or final != 0:
        raise RuntimeError(
            "Pre-SEND_DA verification D0 failed"
        )

    susbdl = s3c.u32le(
        low2,
        s3c.S_USBDL,
    )

    gate = low2[
        s3c.G_DA_VERIFIED
    ]

    print()
    print("[Pre-SEND_DA state]")
    print(
        f"  S-USBDL = "
        f"0x{susbdl:08X}"
    )
    print(
        f"  DA gate = "
        f"0x{gate:02X}"
    )

    if susbdl != 0:
        raise RuntimeError(
            "S-USBDL bypass did not persist"
        )

    if gate != 0:
        raise RuntimeError(
            "DA gate unexpectedly nonzero "
            "before SEND_DA"
        )

    # ------------------------------------------------------------
    # Proven Stage 3E-B real DA upload
    # ------------------------------------------------------------

    print()
    print(
        "[Stage 3E-B] Uploading proven "
        "Wiko XFlash Stage 1..."
    )

    s3e.send_da_stage1(
        ep_out,
        ep_in,
        payload,
    )

    # Do NOT call the old verify_after_send() here because that performs
    # another long D0 snapshot unnecessarily. Instead do the smallest
    # required independent verification before jumping.

    hwcode, hwver = (
        stage1.get_hw_code(
            ep_out,
            ep_in,
        )
    )

    print()
    print("[Post-SEND_DA command loop]")
    print(
        f"  HW_CODE = "
        f"0x{hwcode:04X}"
    )

    if hwcode != EXPECTED_HW_CODE:
        raise RuntimeError(
            "Command loop did not survive SEND_DA"
        )

    # Fresh state readback proving gate became 1.
    _, low3, initial, final = (
        s3c.wrapped_d0_snapshot(
            ep_out,
            ep_in,
            snapshot_end,
        )
    )

    if initial != 0 or final != 0:
        raise RuntimeError(
            "Post-SEND_DA state D0 failed"
        )

    susbdl_after = s3c.u32le(
        low3,
        s3c.S_USBDL,
    )

    gate_after = low3[
        s3c.G_DA_VERIFIED
    ]

    print()
    print("[Post-SEND_DA state]")
    print(
        f"  S-USBDL = "
        f"0x{susbdl_after:08X}"
    )
    print(
        f"  DA gate = "
        f"0x{gate_after:02X}"
    )

    if susbdl_after != 0:
        raise RuntimeError(
            "S-USBDL unexpectedly changed"
        )

    if gate_after != 1:
        raise RuntimeError(
            "DA gate was not set"
        )

    print()
    print("  Stage 3E-B prerequisites: PASS")


def main():
    print(
        "T408DL_preloader_stage3f_jump_wiko.py"
    )
    print(
        "Stage 3F: execute accepted Wiko XFlash Stage 1"
    )
    print("=" * 72)

    print()
    print("BOUNDARY:")
    print(
        "  - proven Stage 3C bypass"
    )
    print(
        "  - proven Stage 3E-B Wiko DA upload"
    )
    print(
        "  - one JUMP_DA"
    )
    print(
        "  - read first DA byte only"
    )
    print(
        "  - NO response to DA"
    )
    print(
        "  - NO XFlash sync sequence"
    )
    print(
        "  - NO storage access"
    )
    print(
        "  - NO flash writes"
    )

    da_path = (
        Path(sys.argv[1])
        if len(sys.argv) > 1
        else s3e.DEFAULT_DA
    )

    # Exact Stage-1 extraction already proven in Stage 3E-B.
    payload = s3e.locate_stage1(
        da_path
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
            f"  HW_CODE = "
            f"0x{hwcode:04X}"
        )

        if hwcode != EXPECTED_HW_CODE:
            raise RuntimeError(
                f"Unexpected HW_CODE "
                f"0x{hwcode:04X}"
            )

        # Reproduce all proven prerequisites.
        establish_stage3e(
            ep_out,
            ep_in,
            payload,
        )

        print()
        print("=" * 72)
        print(
            "ABOUT TO EXECUTE WIKO XFLASH STAGE 1"
        )
        print("=" * 72)
        print(
            f"Entry = "
            f"0x{DA_ENTRY:08X}"
        )
        print(
            "After JUMP_DA the script will "
            "ONLY read one byte."
        )
        print(
            "It will transmit NOTHING to the DA."
        )

        # --------------------------------------------------------
        # Stage 3F
        # --------------------------------------------------------

        jump_da_only(
            ep_out,
            ep_in,
        )

        observe_first_da_byte(
            ep_in,
        )

        print()
        print("=" * 72)
        print("STAGE 3F SUCCESS")
        print("=" * 72)

        print(
            "Wiko XFlash Stage 1 executed."
        )
        print(
            "First DA byte was the expected "
            "0xC0 sync marker."
        )
        print(
            "No DA response was transmitted."
        )
        print(
            "No XFlash commands were issued."
        )
        print(
            "No storage operation was attempted."
        )
        print()
        print(
            "CONTROLLED THIRD-PARTY DA EXECUTION: PROVEN"
        )

        return 0

    except KeyboardInterrupt:
        print()
        print(
            "Interrupted by user."
        )
        return 130

    except Exception as exc:
        print()
        print("=" * 72)
        print(
            "STAGE 3F ABORTED / FAILED CLOSED"
        )
        print("=" * 72)
        print(
            f"ERROR: {exc}"
        )
        print()
        print(
            "Do not infer DA execution unless "
            "JUMP_DA status is 0x0000 and the "
            "first DA byte is exactly 0xC0."
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
                    f"Cleanup warning: "
                    f"{exc}"
                )


if __name__ == "__main__":
    sys.exit(main())
