#!/usr/bin/env python3

import sys
import time
import usb.core

import T408DL_preloader_catcher as stage1
import T408DL_preloader_stage3c_susbdl_zero as s3c

EXPECTED_HW_CODE = 0x0699
CMD_SEND_DA = 0xD7

PROBE_ADDR = 0x00220F6C
PROBE_LEN  = 0x38
SIG_LEN    = 0x00000000


def optional_read(ep_in, size, timeout=250):
    try:
        data = bytes(ep_in.read(size, timeout))
        return data
    except usb.core.USBTimeoutError:
        return None
    except Exception as exc:
        print(f"  read({size}) error: {exc}")
        return None


def raw_write(ep_out, data):
    data = bytes(data)
    n = ep_out.write(data, 2000)
    if int(n) != len(data):
        raise RuntimeError(
            f"short USB write: {n}/{len(data)}"
        )


def show_optional(label, ep_in, size=4):
    data = optional_read(ep_in, size)
    if data is None:
        print(f"  {label:<32} = <no reply>")
    else:
        print(
            f"  {label:<32} = "
            f"{data.hex().upper()} ({len(data)} bytes)"
        )
    return data


def establish_and_zero():
    dev = stage1.wait_for_preloader()
    intf, ep_out, ep_in = stage1.setup_usb(dev)

    stage1.sync_mtk(ep_out, ep_in)

    hwcode, hwver = stage1.get_hw_code(
        ep_out, ep_in
    )

    if hwcode != EXPECTED_HW_CODE:
        raise RuntimeError(
            f"unexpected HW_CODE 0x{hwcode:04X}"
        )

    print(
        f"  HW_CODE = 0x{hwcode:04X}, "
        f"HW_VER = 0x{hwver:04X}"
    )

    s3c.disable_watchdog(
        ep_out, ep_in
    )

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
            "initial D0 failed"
        )

    replay = s3c.build_stage3c_replay(
        wire,
        low,
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

    _, low2, initial, final = (
        s3c.wrapped_d0_snapshot(
            ep_out,
            ep_in,
            snapshot_end,
        )
    )

    if initial != 0 or final != 0:
        raise RuntimeError(
            "post-zero D0 failed"
        )

    susbdl = s3c.u32le(
        low2,
        s3c.S_USBDL,
    )

    gate = low2[
        s3c.G_DA_VERIFIED
    ]

    print()
    print("[Gate]")
    print(
        f"  S-USBDL = 0x{susbdl:08X}"
    )
    print(
        f"  DA gate = 0x{gate:02X}"
    )

    if susbdl != 0:
        raise RuntimeError(
            "S-USBDL is not zero"
        )

    if gate != 0:
        raise RuntimeError(
            "DA gate unexpectedly nonzero"
        )

    return dev, ep_out, ep_in


def probe_header(ep_out, ep_in):
    print()
    print("=" * 72)
    print("SEND_DA HEADER CHARACTERIZATION")
    print("=" * 72)
    print(
        "No payload will be transmitted."
    )
    print()

    # D7 itself is known to echo.
    print("[1] SEND_DA opcode")
    raw_write(
        ep_out,
        bytes([CMD_SEND_DA]),
    )

    cmd_reply = optional_read(
        ep_in,
        1,
        1000,
    )

    if cmd_reply is None:
        raise RuntimeError(
            "no D7 command reply"
        )

    print(
        f"  command reply                  = "
        f"{cmd_reply.hex().upper()}"
    )

    if cmd_reply != bytes([CMD_SEND_DA]):
        raise RuntimeError(
            "D7 did not echo correctly"
        )

    # Important: see whether TCL sends anything
    # BEFORE we provide the address.
    show_optional(
        "after D7, before address",
        ep_in,
        4,
    )

    print()
    print("[2] Address")
    print(
        f"  TX = {PROBE_ADDR:08X}"
    )

    raw_write(
        ep_out,
        PROBE_ADDR.to_bytes(
            4,
            "big",
        ),
    )

    show_optional(
        "reply after address",
        ep_in,
        4,
    )

    print()
    print("[3] Length")
    print(
        f"  TX = {PROBE_LEN:08X}"
    )

    raw_write(
        ep_out,
        PROBE_LEN.to_bytes(
            4,
            "big",
        ),
    )

    show_optional(
        "reply after length",
        ep_in,
        4,
    )

    print()
    print("[4] Signature length")
    print(
        f"  TX = {SIG_LEN:08X}"
    )

    raw_write(
        ep_out,
        SIG_LEN.to_bytes(
            4,
            "big",
        ),
    )

    # Try both likely response widths.
    r4 = show_optional(
        "4-byte reply after sig_len",
        ep_in,
        4,
    )

    if r4 is None:
        show_optional(
            "2-byte reply after sig_len",
            ep_in,
            2,
        )
    else:
        # TCL returned a 4-byte sig_len response. Probe for the
        # separate 16-bit SEND_DA initial status that may follow it.
        show_optional(
            "16-bit status after sig_len",
            ep_in,
            2,
        )

    print()
    print("=" * 72)
    print("HEADER PROBE COMPLETE")
    print("=" * 72)
    print(
        "Payload was NOT transmitted."
    )
    print(
        "JUMP_DA was NOT issued."
    )


def main():
    print(
        "T408DL Stage 3E SEND_DA "
        "header-framing probe"
    )
    print("=" * 72)

    dev = None

    try:
        dev, ep_out, ep_in = (
            establish_and_zero()
        )

        probe_header(
            ep_out,
            ep_in,
        )

        return 0

    except Exception as exc:
        print()
        print("=" * 72)
        print("ABORTED / FAILED CLOSED")
        print("=" * 72)
        print(f"ERROR: {exc}")
        return 1

    finally:
        if dev is not None:
            print()
            print(
                "Releasing USB session..."
            )
            try:
                stage1.cleanup(dev)
            except Exception as exc:
                print(
                    f"cleanup warning: {exc}"
                )


if __name__ == "__main__":
    sys.exit(main())
