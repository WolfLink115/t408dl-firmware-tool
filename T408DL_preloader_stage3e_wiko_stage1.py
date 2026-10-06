#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import sys
import time
from pathlib import Path

import T408DL_preloader_catcher as stage1
import T408DL_preloader_stage3c_susbdl_zero as s3c


EXPECTED_HW_CODE = 0x0699
CMD_SEND_DA = 0xD7

BASE_DIR = Path(__file__).resolve().parent

DEFAULT_DA = (
    BASE_DIR
    / "wiko-da"
    / "DA_SWSEC_1836_K510BG_9.0_WIK_FR_31.bin"
)

# Geometry independently seen in the old MTKClient run.
MTK_LOAD_ADDRESS = 0x00200000
STAGE1_LENGTH = 0x0001C848
STAGE1_SIG_LEN = 0x00000100

# Actual TCL stock Preloader staging buffer, recovered from disassembly.
TCL_INTERNAL_DA_BUFFER = 0x40200000

# Beginning of the exact xflash stage-1 stream recorded in the old
# MTKClient debug log. Used only to locate the stage inside the DA file.
STAGE1_NEEDLE = bytes.fromhex(
    "FFFFFFEAE90900FA00000FE1C010A0E3"
    "010080E100F02FE104B0A0E105C0A0E1"
)

USB_TIMEOUT_MS = 5000
WRITE_CHUNK = 0x4000


def checksum16_xor_le(data: bytes) -> int:
    b = bytes(data)

    if len(b) & 1:
        b += b"\x00"

    result = 0

    for off in range(0, len(b), 2):
        result ^= int.from_bytes(
            b[off:off + 2],
            "little",
        )

    return result & 0xFFFF


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


def locate_stage1(da_path: Path) -> bytes:
    print()
    print("[DA] Loading Wiko DA")
    print(f"  path = {da_path}")

    if not da_path.is_file():
        raise RuntimeError(
            f"DA file not found: {da_path}"
        )

    blob = da_path.read_bytes()

    print(f"  full file size = 0x{len(blob):X}")
    print(
        f"  full SHA-256   = "
        f"{hashlib.sha256(blob).hexdigest()}"
    )

    positions = []

    start = 0

    while True:
        off = blob.find(
            STAGE1_NEEDLE,
            start,
        )

        if off < 0:
            break

        positions.append(off)
        start = off + 1

    print(
        f"  Stage-1 signature matches = "
        f"{len(positions)}"
    )

    if len(positions) != 1:
        raise RuntimeError(
            "Could not uniquely locate the exact "
            "Wiko xflash Stage-1 stream"
        )

    offset = positions[0]
    end = offset + STAGE1_LENGTH

    if end > len(blob):
        raise RuntimeError(
            "Stage-1 region extends beyond DA file"
        )

    payload = blob[
        offset:end
    ]

    if not payload.startswith(
        STAGE1_NEEDLE
    ):
        raise RuntimeError(
            "Stage-1 signature mismatch after extraction"
        )

    print(f"  Stage-1 file offset = 0x{offset:X}")
    print(f"  Stage-1 length      = 0x{len(payload):X}")
    print(
        f"  Stage-1 SHA-256     = "
        f"{hashlib.sha256(payload).hexdigest()}"
    )
    print(
        f"  Stage-1 XOR16       = "
        f"0x{checksum16_xor_le(payload):04X}"
    )

    if len(payload) != STAGE1_LENGTH:
        raise RuntimeError(
            "Stage-1 length mismatch"
        )

    if len(payload) > 0x40000:
        raise RuntimeError(
            "Stage-1 exceeds conservative 256-KiB ceiling"
        )

    return payload


def send_da_stage1(ep_out, ep_in, payload):
    host_checksum = checksum16_xor_le(
        payload
    )

    print()
    print("=" * 72)
    print("STAGE 3E-B — WIKO XFLASH STAGE-1 SEND_DA")
    print("=" * 72)

    print(
        f"  host address field  = "
        f"0x{MTK_LOAD_ADDRESS:08X}"
    )
    print(
        f"  TCL internal buffer = "
        f"0x{TCL_INTERNAL_DA_BUFFER:08X}"
    )
    print(
        f"  length              = "
        f"0x{len(payload):X}"
    )
    print(
        f"  signature length    = "
        f"0x{STAGE1_SIG_LEN:X}"
    )
    print(
        f"  expected checksum   = "
        f"0x{host_checksum:04X}"
    )
    print()
    print("  JUMP_DA = DISABLED")

    # -----------------------------------------------------------
    # SEND_DA opcode
    # -----------------------------------------------------------

    write_exact(
        ep_out,
        bytes([CMD_SEND_DA]),
    )

    cmd_reply = s3c.read_exact(
        ep_in,
        1,
        USB_TIMEOUT_MS,
    )

    print()
    print("[SEND_DA header]")
    print(
        f"  opcode reply = "
        f"{cmd_reply.hex().upper()}"
    )

    if cmd_reply != bytes(
        [CMD_SEND_DA]
    ):
        raise RuntimeError(
            "SEND_DA opcode echo mismatch"
        )

    # -----------------------------------------------------------
    # Address field
    #
    # Before bypass MTKClient saw a normal echo.
    # After our Stage-3C return path we have observed 00000000.
    # Either is accepted diagnostically.
    # -----------------------------------------------------------

    addr_raw = (
        MTK_LOAD_ADDRESS
        .to_bytes(4, "big")
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
        f"  address TX   = "
        f"{addr_raw.hex().upper()}"
    )
    print(
        f"  address RX   = "
        f"{addr_reply.hex().upper()}"
    )

    if addr_reply not in (
        addr_raw,
        b"\x00\x00\x00\x00",
    ):
        raise RuntimeError(
            "Unexpected SEND_DA address response"
        )

    # -----------------------------------------------------------
    # Length
    # -----------------------------------------------------------

    length_raw = (
        len(payload)
        .to_bytes(4, "big")
    )

    write_exact(
        ep_out,
        length_raw,
    )

    length_reply = s3c.read_exact(
        ep_in,
        4,
        USB_TIMEOUT_MS,
    )

    print(
        f"  length TX    = "
        f"{length_raw.hex().upper()}"
    )
    print(
        f"  length RX    = "
        f"{length_reply.hex().upper()}"
    )

    if length_reply != length_raw:
        raise RuntimeError(
            "SEND_DA length response mismatch"
        )

    # -----------------------------------------------------------
    # Signature length
    # -----------------------------------------------------------

    sig_raw = (
        STAGE1_SIG_LEN
        .to_bytes(4, "big")
    )

    write_exact(
        ep_out,
        sig_raw,
    )

    sig_reply = s3c.read_exact(
        ep_in,
        4,
        USB_TIMEOUT_MS,
    )

    print(
        f"  sig_len TX   = "
        f"{sig_raw.hex().upper()}"
    )
    print(
        f"  sig_len RX   = "
        f"{sig_reply.hex().upper()}"
    )

    # As with address, preserve both behaviors we've seen / expect:
    # normal echo or TCL post-bypass zero response.
    if sig_reply not in (
        sig_raw,
        b"\x00\x00\x00\x00",
    ):
        raise RuntimeError(
            "Unexpected SEND_DA sig_len response"
        )

    initial = s3c.rword(
        ep_in
    )

    print(
        f"  initial status = "
        f"0x{initial:04X}"
    )

    if initial != 0x0000:
        raise RuntimeError(
            f"SEND_DA header rejected: "
            f"0x{initial:04X}"
        )

    # -----------------------------------------------------------
    # Actual Wiko Stage-1 payload
    # -----------------------------------------------------------

    print()
    print("[SEND_DA payload]")

    sent = 0
    started = time.monotonic()
    next_report = 0x4000

    while sent < len(payload):
        block = payload[
            sent:
            sent + WRITE_CHUNK
        ]

        write_exact(
            ep_out,
            block,
        )

        sent += len(block)

        if (
            sent >= next_report
            or sent == len(payload)
        ):
            elapsed = (
                time.monotonic()
                - started
            )

            pct = (
                sent * 100.0
                / len(payload)
            )

            print(
                f"  progress = "
                f"0x{sent:X}/0x{len(payload):X} "
                f"({pct:.1f}%, "
                f"{elapsed:.3f}s)"
            )

            while (
                next_report <= sent
            ):
                next_report += 0x4000

    # SEND_DA calculates checksum over the internal staging buffer
    # and returns it before the final status.
    device_checksum = s3c.rword(
        ep_in
    )

    final_status = s3c.rword(
        ep_in
    )

    print()
    print("[SEND_DA result]")

    print(
        f"  host checksum   = "
        f"0x{host_checksum:04X}"
    )
    print(
        f"  device checksum = "
        f"0x{device_checksum:04X}"
    )
    print(
        f"  final status    = "
        f"0x{final_status:04X}"
    )

    if (
        device_checksum
        != host_checksum
    ):
        raise RuntimeError(
            "Wiko Stage-1 checksum mismatch"
        )

    if final_status != 0:
        raise RuntimeError(
            f"SEND_DA final status "
            f"0x{final_status:04X}"
        )

    print()
    print("  Wiko Stage-1 SEND_DA: PASS")


def verify_after_send(ep_out, ep_in):
    print()
    print("[Verify] Command loop")

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
            "Command loop did not survive"
        )

    print(
        "  command loop survived: PASS"
    )

    snapshot_end = (
        s3c.G_DA_VERIFIED + 2
    ) & ~1

    _, low, initial, final = (
        s3c.wrapped_d0_snapshot(
            ep_out,
            ep_in,
            snapshot_end,
        )
    )

    if (
        initial != 0
        or final != 0
    ):
        raise RuntimeError(
            "Post-SEND_DA D0 failed"
        )

    susbdl = s3c.u32le(
        low,
        s3c.S_USBDL,
    )

    gate = low[
        s3c.G_DA_VERIFIED
    ]

    print()
    print("[Verify] Security state")

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
            "S-USBDL did not remain zero"
        )

    if gate != 1:
        raise RuntimeError(
            "DA gate did not become 1"
        )

    print(
        "  S-USBDL zero: PASS"
    )
    print(
        "  DA gate set:  PASS"
    )


def main():
    print(
        "T408DL_preloader_stage3e_wiko_stage1.py"
    )
    print(
        "Stage 3E-B: upload real Wiko xflash Stage 1"
    )
    print("=" * 72)

    print()
    print("BOUNDARY:")
    print(
        "  - reproduce proven Stage 3C"
    )
    print(
        "  - SEND_DA actual Wiko Stage 1"
    )
    print(
        "  - NO JUMP_DA"
    )
    print(
        "  - NO DA execution"
    )
    print(
        "  - NO flash/storage access"
    )

    da_path = (
        Path(sys.argv[1])
        if len(sys.argv) > 1
        else DEFAULT_DA
    )

    payload = locate_stage1(
        da_path
    )

    s3c.verify_stock_image_if_present()

    dev = None

    try:
        print()
        print("[Stage 1] Waiting for Preloader...")

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

        if hwcode != EXPECTED_HW_CODE:
            raise RuntimeError(
                f"Unexpected HW_CODE "
                f"0x{hwcode:04X}"
            )

        s3c.disable_watchdog(
            ep_out,
            ep_in,
        )

        # -------------------------------------------------------
        # Reproduce proven Stage 3C.
        # -------------------------------------------------------

        snapshot_end = (
            s3c.G_DA_VERIFIED + 2
        ) & ~1

        wire, low, initial, final = (
            s3c.wrapped_d0_snapshot(
                ep_out,
                ep_in,
                snapshot_end,
            )
        )

        if (
            initial != 0
            or final != 0
        ):
            raise RuntimeError(
                "Initial D0 failed"
            )

        replay = (
            s3c.build_stage3c_replay(
                wire,
                low,
            )
        )

        print()
        print(
            "[Stage 3C] Zeroing S-USBDL..."
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

        # Independent zero verification before real DA upload.
        _, low2, initial, final = (
            s3c.wrapped_d0_snapshot(
                ep_out,
                ep_in,
                snapshot_end,
            )
        )

        if (
            initial != 0
            or final != 0
        ):
            raise RuntimeError(
                "Pre-DA verification D0 failed"
            )

        susbdl = s3c.u32le(
            low2,
            s3c.S_USBDL,
        )

        gate = low2[
            s3c.G_DA_VERIFIED
        ]

        print()
        print("[Gate before real SEND_DA]")
        print(
            f"  S-USBDL = "
            f"0x{susbdl:08X}"
        )
        print(
            f"  DA gate = "
            f"0x{gate:02X}"
        )

        if (
            susbdl != 0
            or gate != 0
        ):
            raise RuntimeError(
                "Pre-SEND_DA state invalid"
            )

        # -------------------------------------------------------
        # Stage 3E-B
        # -------------------------------------------------------

        send_da_stage1(
            ep_out,
            ep_in,
            payload,
        )

        verify_after_send(
            ep_out,
            ep_in,
        )

        print()
        print("=" * 72)
        print("STAGE 3E-B SUCCESS")
        print("=" * 72)
        print(
            "Real Wiko xflash Stage 1 was accepted."
        )
        print(
            "Device checksum matched host checksum."
        )
        print(
            "SEND_DA final status was 0x0000."
        )
        print(
            "DA gate is 0x01."
        )
        print(
            "Command loop remains alive."
        )
        print()
        print(
            "The loader was NOT executed."
        )
        print(
            "NO JUMP_DA was sent."
        )
        print(
            "NO flash/storage operation occurred."
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
            "STAGE 3E-B ABORTED / FAILED CLOSED"
        )
        print("=" * 72)
        print(f"ERROR: {exc}")
        return 1

    finally:
        if dev is not None:
            print()
            print(
                "Releasing Preloader USB session..."
            )

            try:
                stage1.cleanup(dev)
            except Exception as exc:
                print(
                    f"Cleanup warning: {exc}"
                )


if __name__ == "__main__":
    sys.exit(main())
