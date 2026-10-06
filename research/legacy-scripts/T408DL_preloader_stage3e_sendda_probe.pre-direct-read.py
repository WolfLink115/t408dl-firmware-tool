#!/usr/bin/env python3
"""
T408DL Stage 3E-A — inert SEND_DA probe.

Purpose:
  1. Establish the proven Stage-1 session.
  2. Disable WDT.
  3. Reproduce proven Stage-3C S-USBDL -> 0.
  4. Independently verify S-USBDL == 0.
  5. SEND_DA a tiny inert marker to SRAM scratch.
  6. Do NOT JUMP_DA.
  7. Independently read the SRAM alias back and compare bytes.
  8. Record DA-gate state and prove the command loop still works.

No flash/storage writes.
No DA execution.
"""

from __future__ import annotations

import sys
import time

import T408DL_preloader_catcher as stage1
import T408DL_preloader_stage3c_susbdl_zero as s3c


EXPECTED_HW_CODE = 0x0699

CMD_SEND_DA = 0xD7

# Old experimental SRAM scratch region.
PROBE_ADDR = 0x00220F6C

# Read-alias observed for 0x00220xxx -> 0x000E0xxx.
PROBE_ALIAS = 0x000E0F6C

# Deliberately < 64 bytes and even-sized, avoiding any ambiguity around
# a USB max-packet-sized final transfer.
PROBE = (
    b"T408DL-STAGE3E-SEND_DA-PROBE-v1|"
    + bytes(range(1, 25))
)

SIG_LEN = 0

USB_TIMEOUT_MS = 5000


def checksum16_xor_le(data: bytes) -> int:
    """
    MediaTek legacy SEND_DA checksum:
    XOR successive little-endian 16-bit words.
    """
    buf = bytes(data)

    if len(buf) & 1:
        buf += b"\x00"

    csum = 0

    for off in range(0, len(buf), 2):
        csum ^= int.from_bytes(buf[off:off + 2], "little")

    return csum & 0xFFFF


def send_da_probe(ep_out, ep_in):
    host_checksum = checksum16_xor_le(PROBE)

    print()
    print("[SEND_DA] Inert Stage 3E-A probe")
    print(f"  destination    = 0x{PROBE_ADDR:08X}")
    print(f"  length         = 0x{len(PROBE):X} ({len(PROBE)} bytes)")
    print(f"  signature len  = 0x{SIG_LEN:X}")
    print(f"  host checksum  = 0x{host_checksum:04X}")
    print("  execution      = NEVER")

    def write_exact(data):
        data = bytes(data)
        written = ep_out.write(data, USB_TIMEOUT_MS)
        if int(written) != len(data):
            raise RuntimeError(
                f"short USB write: {written}/{len(data)}"
            )

    # ---------------------------------------------------------------
    # TCL-specific SEND_DA framing, empirically proven on this device:
    #
    #   D7       -> D7
    #   address  -> 00000000
    #   length   -> echoed length
    #   sig_len  -> echoed sig_len
    #             -> 16-bit initial status
    #
    # Payload follows only after initial status == 0000.
    # ---------------------------------------------------------------

    write_exact(bytes([CMD_SEND_DA]))

    cmd_reply = s3c.read_exact(
        ep_in,
        1,
        USB_TIMEOUT_MS,
    )

    print(f"  command reply   = {cmd_reply.hex().upper()}")

    if cmd_reply != bytes([CMD_SEND_DA]):
        raise RuntimeError(
            f"SEND_DA opcode mismatch: {cmd_reply.hex()}"
        )

    # Address.
    write_exact(
        PROBE_ADDR.to_bytes(4, "big")
    )

    addr_reply = s3c.read_exact(
        ep_in,
        4,
        USB_TIMEOUT_MS,
    )

    print(f"  address reply   = {addr_reply.hex().upper()}")

    # This is NOT an address echo on the TCL Preloader.
    # Two separate header probes proved it is exactly 00000000.
    if addr_reply != b"\x00\x00\x00\x00":
        raise RuntimeError(
            "unexpected TCL SEND_DA address response: "
            f"{addr_reply.hex().upper()}"
        )

    # Payload length.
    length_raw = len(PROBE).to_bytes(4, "big")

    write_exact(length_raw)

    length_reply = s3c.read_exact(
        ep_in,
        4,
        USB_TIMEOUT_MS,
    )

    print(f"  length reply    = {length_reply.hex().upper()}")

    if length_reply != length_raw:
        raise RuntimeError(
            "SEND_DA length response mismatch"
        )

    # Signature length.
    sig_raw = SIG_LEN.to_bytes(4, "big")

    write_exact(sig_raw)

    sig_reply = s3c.read_exact(
        ep_in,
        4,
        USB_TIMEOUT_MS,
    )

    print(f"  sig_len reply   = {sig_reply.hex().upper()}")

    if sig_reply != sig_raw:
        raise RuntimeError(
            "SEND_DA signature-length response mismatch"
        )

    # Proven separate 16-bit initial status follows sig_len.
    initial = s3c.rword(ep_in)

    print(f"  initial status  = 0x{initial:04X}")

    if initial != 0x0000:
        raise RuntimeError(
            f"SEND_DA header rejected: 0x{initial:04X}"
        )

    # ---------------------------------------------------------------
    # Payload
    # ---------------------------------------------------------------

    print()
    print("[SEND_DA] Streaming inert payload...")

    started = time.monotonic()

    write_exact(PROBE)

    elapsed = time.monotonic() - started

    print(f"  host transmitted = {len(PROBE)} bytes")
    print(f"  elapsed          = {elapsed:.3f}s")

    # Legacy SEND_DA result:
    #   16-bit checksum
    #   16-bit final status
    device_checksum = s3c.rword(ep_in)
    final_status = s3c.rword(ep_in)

    print()
    print("[SEND_DA] Result")
    print(f"  host checksum    = 0x{host_checksum:04X}")
    print(f"  device checksum  = 0x{device_checksum:04X}")
    print(f"  final status     = 0x{final_status:04X}")

    if device_checksum != host_checksum:
        raise RuntimeError(
            "SEND_DA checksum mismatch: "
            f"device=0x{device_checksum:04X} "
            f"host=0x{host_checksum:04X}"
        )

    if final_status != 0x0000:
        raise RuntimeError(
            f"SEND_DA final status failure: "
            f"0x{final_status:04X}"
        )

    print("  SEND_DA transaction: PASS")

    return initial, device_checksum, final_status


def read_post_send_state(ep_out, ep_in):
    """
    One fresh D0 covers:
      - scratch alias @ 0x000E0F6C
      - S-USBDL      @ 0x0010043C
      - DA gate      @ 0x0010935D
    """
    end = max(
        PROBE_ALIAS + len(PROBE),
        s3c.G_DA_VERIFIED + 2,
    )

    end = (end + 1) & ~1

    _, low, initial, final = s3c.wrapped_d0_snapshot(
        ep_out,
        ep_in,
        end,
    )

    if initial != 0x0000 or final != 0x0000:
        raise RuntimeError(
            "Post-SEND_DA D0 did not complete cleanly"
        )

    staged = bytes(
        low[PROBE_ALIAS:PROBE_ALIAS + len(PROBE)]
    )

    susbdl = s3c.u32le(low, s3c.S_USBDL)
    gate = low[s3c.G_DA_VERIFIED]

    print()
    print("[Verify] Independent post-SEND_DA readback")
    print(
        f"  S-USBDL @ 0x{s3c.S_USBDL:08X} "
        f"= 0x{susbdl:08X}"
    )
    print(
        f"  DA gate  @ 0x{s3c.G_DA_VERIFIED:08X} "
        f"= 0x{gate:02X}"
    )
    print(
        f"  probe alias @ 0x{PROBE_ALIAS:08X}"
    )

    print(f"  expected = {PROBE.hex().upper()}")
    print(f"  readback = {staged.hex().upper()}")

    if susbdl != 0x00000000:
        raise RuntimeError(
            f"S-USBDL unexpectedly changed to "
            f"0x{susbdl:08X}"
        )

    if staged != PROBE:
        raise RuntimeError(
            "SEND_DA payload did not survive at the "
            "expected SRAM alias"
        )

    print()
    print("  S-USBDL still zero: PASS")
    print("  staged payload:      PASS")

    if gate == 0x01:
        print("  DA gate:             0x01")
    elif gate == 0x00:
        print("  DA gate:             0x00")
    else:
        print(
            f"  DA gate:             unexpected 0x{gate:02X}"
        )

    return susbdl, gate, staged


def main():
    print("T408DL_preloader_stage3e_sendda_probe.py")
    print("Stage 3E-A: inert SEND_DA proof")
    print("=" * 72)
    print()
    print("BOUNDARY:")
    print("  - proven volatile Stage 3C zero-store")
    print("  - one tiny inert SEND_DA transfer")
    print("  - NO JUMP_DA")
    print("  - NO executable payload")
    print("  - NO flash/storage access")
    print("  - Stage 1 / Stage 3C files remain untouched")

    if len(PROBE) >= 64:
        raise RuntimeError(
            "Probe unexpectedly reached USB packet size"
        )

    if len(PROBE) & 1:
        raise RuntimeError(
            "Probe must remain even-sized"
        )

    s3c.verify_stock_image_if_present()

    dev = None

    try:
        print()
        print("[Stage 1] Waiting for Preloader...")
        dev = stage1.wait_for_preloader()

        print("[Stage 1] Setting up USB...")
        intf, ep_out, ep_in = stage1.setup_usb(dev)

        print("[Stage 1] Synchronizing...")
        stage1.sync_mtk(ep_out, ep_in)

        print("[Stage 1] Checking HW_CODE...")
        hwcode, hwver = stage1.get_hw_code(ep_out, ep_in)

        print(f"  HW_CODE = 0x{hwcode:04X}")
        print(f"  HW_VER  = 0x{hwver:04X}")

        if hwcode != EXPECTED_HW_CODE:
            raise RuntimeError(
                f"Unexpected HW_CODE 0x{hwcode:04X}"
            )

        s3c.disable_watchdog(ep_out, ep_in)

        # ---------------------------------------------------------------
        # Reproduce the already-proven Stage 3C transition.
        # ---------------------------------------------------------------

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

        if initial != 0 or final != 0:
            raise RuntimeError(
                "Initial D0 snapshot failed"
            )

        replay = s3c.build_stage3c_replay(
            wire,
            low,
        )

        print()
        print("[Stage 3C] Applying proven S-USBDL zero-store...")

        s3c.d3_write_replay(
            ep_out,
            ep_in,
            replay,
        )

        s3c.verify_hw_code(
            ep_out,
            ep_in,
        )

        # Explicit fresh state check before SEND_DA.
        _, low_zero, initial, final = (
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
            low_zero,
            s3c.S_USBDL,
        )

        gate_before = low_zero[
            s3c.G_DA_VERIFIED
        ]

        print()
        print("[Gate] Immediately before SEND_DA")
        print(
            f"  S-USBDL = 0x{susbdl:08X}"
        )
        print(
            f"  DA gate = 0x{gate_before:02X}"
        )

        if susbdl != 0:
            raise RuntimeError(
                "S-USBDL is not zero; refusing SEND_DA"
            )

        if gate_before != 0:
            raise RuntimeError(
                "DA gate is not zero before SEND_DA; refusing"
            )

        # ---------------------------------------------------------------
        # Stage 3E-A: SEND_DA only.
        # ---------------------------------------------------------------

        print()
        print("=" * 72)
        print("ABOUT TO ISSUE SEND_DA WITH INERT DATA")
        print("=" * 72)
        print(
            f"destination = 0x{PROBE_ADDR:08X}"
        )
        print(
            f"bytes       = {len(PROBE)}"
        )
        print("JUMP_DA     = DISABLED")
        print()

        send_da_probe(
            ep_out,
            ep_in,
        )

        # If SEND_DA returned cleanly, command loop must still respond.
        print()
        print("[Verify] GET_HW_CODE after SEND_DA")

        hwcode2, hwver2 = stage1.get_hw_code(
            ep_out,
            ep_in,
        )

        print(
            f"  HW_CODE = 0x{hwcode2:04X}"
        )
        print(
            f"  HW_VER  = 0x{hwver2:04X}"
        )

        if hwcode2 != EXPECTED_HW_CODE:
            raise RuntimeError(
                "Command loop did not survive SEND_DA"
            )

        print("  command loop survived: PASS")

        susbdl_after, gate_after, staged = (
            read_post_send_state(
                ep_out,
                ep_in,
            )
        )

        print()
        print("=" * 72)
        print("STAGE 3E-A SUCCESS")
        print("=" * 72)
        print("SEND_DA header accepted.")
        print("Payload checksum matched.")
        print("SEND_DA final status was 0x0000.")
        print("Payload independently read back from SRAM.")
        print("S-USBDL remained 0x00000000.")
        print(
            f"DA gate after SEND_DA = 0x{gate_after:02X}"
        )
        print("Command loop remains functional.")
        print()
        print("NO JUMP_DA was attempted.")
        print("NO flash/storage access was attempted.")

        return 0

    except KeyboardInterrupt:
        print()
        print("Interrupted.")
        return 130

    except Exception as exc:
        print()
        print("=" * 72)
        print("STAGE 3E-A ABORTED / FAILED CLOSED")
        print("=" * 72)
        print(f"ERROR: {exc}")
        print()
        print(
            "Do not infer SEND_DA success unless checksum, "
            "final status, independent SRAM readback, and "
            "command-loop survival all pass."
        )
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
