#!/usr/bin/env python3

from __future__ import annotations

import struct
import sys

import T408DL_preloader_catcher as stage1
import T408DL_preloader_stage3c_susbdl_zero as s3c
import T408DL_preloader_stage3e_wiko_stage1 as s3e
import T408DL_preloader_stage3f_jump_wiko as s3f
import T408DL_preloader_stage3g_xflash_sync as s3g

class Cmd:
    # XFlash command IDs from upstream mtkclient xflash_param.py.
    DEVICE_CTRL = 0x010009

    GET_EMMC_INFO = 0x040001
    GET_DA_VERSION = 0x040005
    GET_PACKET_LENGTH = 0x040007
    GET_USB_SPEED = 0x04000B
    GET_RAM_INFO = 0x04000C
    GET_CHIP_ID = 0x04000D
    SLA_ENABLED_STATUS = 0x040016


USB_TIMEOUT_MS = 5000
cmd = Cmd()


def status_name(v):
    return f"0x{v:08X}"


def devctrl_read(ep_out, ep_in, subcmd, name):
    """
    Current XFlash DEVICE_CTRL flow:

      DEVICE_CTRL
        -> status
      subcommand
        -> status
      response packet
        -> trailing status

    This function is READ-ONLY at the DA protocol level.
    """

    print()
    print("=" * 72)
    print(f"DEVICE_CTRL: {name}")
    print("=" * 72)
    print(f"  DEVICE_CTRL = 0x{cmd.DEVICE_CTRL:08X}")
    print(f"  subcommand  = 0x{subcmd:08X}")

    # DEVICE_CTRL
    s3g.xsend(
        ep_out,
        cmd.DEVICE_CTRL,
    )

    st = s3g.read_status(
        ep_in,
    )

    print(
        f"  DEVICE_CTRL status = "
        f"{status_name(st)}"
    )

    if st != 0:
        raise RuntimeError(
            f"{name}: DEVICE_CTRL rejected: "
            f"{status_name(st)}"
        )

    # Subcommand
    s3g.xsend(
        ep_out,
        subcmd,
    )

    st = s3g.read_status(
        ep_in,
    )

    print(
        f"  subcommand status   = "
        f"{status_name(st)}"
    )

    if st != 0:
        raise RuntimeError(
            f"{name}: subcommand rejected: "
            f"{status_name(st)}"
        )

    # Data response
    dtype, data = s3g.xread_packet(
        ep_in,
    )

    print(
        f"  response datatype   = {dtype}"
    )
    print(
        f"  response length     = "
        f"0x{len(data):X} ({len(data)} bytes)"
    )
    print(
        f"  response raw        = "
        f"{data.hex().upper()}"
    )

    # Final status associated with returned data.
    st = s3g.read_status(
        ep_in,
    )

    print(
        f"  trailing status     = "
        f"{status_name(st)}"
    )

    if st != 0:
        raise RuntimeError(
            f"{name}: trailing status: "
            f"{status_name(st)}"
        )

    return data


def print_da_version(data):
    print()
    print("[Decoded DA version]")

    try:
        value = data.rstrip(b"\x00").decode(
            "utf-8",
            errors="replace",
        )
    except Exception:
        value = repr(data)

    print(f"  {value}")


def print_chip_id(data):
    print()
    print("[Decoded chip ID]")

    if len(data) < 10:
        print(
            "  response too short for "
            "standard XFlash chip-id structure"
        )
        return

    values = struct.unpack(
        "<HHHHH",
        data[:10],
    )

    names = (
        "HW_CODE",
        "HW_SUB_CODE",
        "HW_VERSION",
        "SW_VERSION",
        "CHIP_EVOLUTION",
    )

    for name, value in zip(
        names,
        values,
    ):
        print(
            f"  {name:14s} = "
            f"0x{value:04X}"
        )


def print_ram_info(data):
    print()
    print("[Decoded RAM information]")

    if len(data) == 24:
        vals = struct.unpack(
            "<IIIIII",
            data,
        )

    elif len(data) == 48:
        vals = struct.unpack(
            "<QQQQQQ",
            data,
        )

    else:
        print(
            f"  unknown RAM-info structure "
            f"length: {len(data)}"
        )
        return

    (
        sram_type,
        sram_base,
        sram_size,
        dram_type,
        dram_base,
        dram_size,
    ) = vals

    print(
        f"  SRAM type = 0x{sram_type:X}"
    )
    print(
        f"  SRAM base = 0x{sram_base:X}"
    )
    print(
        f"  SRAM size = 0x{sram_size:X}"
    )

    print(
        f"  DRAM type = 0x{dram_type:X}"
    )
    print(
        f"  DRAM base = 0x{dram_base:X}"
    )
    print(
        f"  DRAM size = 0x{dram_size:X}"
    )

    if dram_size:
        print(
            f"  DRAM MiB  = "
            f"{dram_size / 1024 / 1024:.2f}"
        )


def print_packet_lengths(data):
    print()
    print("[Decoded packet lengths]")

    if len(data) < 8:
        print(
            "  response too short"
        )
        return

    write_len, read_len = struct.unpack(
        "<II",
        data[:8],
    )

    print(
        f"  write packet length = "
        f"0x{write_len:X}"
    )

    print(
        f"  read packet length  = "
        f"0x{read_len:X}"
    )


def print_usb_speed(data):
    print()
    print("[Decoded USB speed]")

    try:
        text = data.rstrip(
            b"\x00"
        ).decode(
            "ascii",
            errors="replace",
        )

        print(
            f"  {text!r}"
        )

    except Exception:
        print(
            f"  {data.hex().upper()}"
        )


def print_sla(data):
    print()
    print("[Decoded DA SLA status]")

    if not data:
        print(
            "  empty response"
        )
        return

    value = int.from_bytes(
        data,
        "little",
    )

    print(
        f"  value = 0x{value:X}"
    )


def print_emmc_info(data):
    print()
    print("[Decoded eMMC information]")

    print(
        f"  raw length = "
        f"0x{len(data):X} ({len(data)} bytes)"
    )
    print(
        f"  raw        = "
        f"{data.hex().upper()}"
    )

    # Standard XFlash eMMC-info structure:
    #
    #   u32 type
    #   u32 block_size
    #   u64 boot1
    #   u64 boot2
    #   u64 rpmb
    #   u64 gp1
    #   u64 gp2
    #   u64 gp3
    #   u64 gp4
    #   u64 user
    #   u8  cid[16]
    #   u64 fwver
    #
    # = 96 bytes minimum.

    if len(data) < 96:
        print()
        print(
            "  Response is shorter than the "
            "standard 96-byte XFlash eMMC structure."
        )
        print(
            "  Leaving it undecoded rather than guessing."
        )
        return

    pos = 0

    emmc_type, block_size = struct.unpack_from(
        "<II",
        data,
        pos,
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
        "<QQQQQQQQ",
        data,
        pos,
    )
    pos += 64

    cid = data[pos:pos + 16]
    pos += 16

    fwver = struct.unpack_from(
        "<Q",
        data,
        pos,
    )[0]
    pos += 8

    extra = data[pos:]

    print()
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

    print(
        f"  GP1        = 0x{gp1:X}"
    )
    print(
        f"  GP2        = 0x{gp2:X}"
    )
    print(
        f"  GP3        = 0x{gp3:X}"
    )
    print(
        f"  GP4        = 0x{gp4:X}"
    )

    print(
        f"  USER       = 0x{user:X} "
        f"({user / 1024 / 1024 / 1024:.3f} GiB)"
    )

    print(
        f"  CID        = "
        f"{cid.hex().upper()}"
    )

    print(
        f"  FW version = "
        f"0x{fwver:X}"
    )

    if extra:
        print(
            f"  extra      = "
            f"{extra.hex().upper()}"
        )


def main():
    print(
        "T408DL_preloader_stage3h_da_info.py"
    )

    print(
        "Stage 3H-B: read-only XFlash "
        "eMMC identification only"
    )

    print("=" * 72)

    print()
    print("BOUNDARY:")
    print("  - reproduce proven Stage 3C")
    print("  - reproduce proven Stage 3E")
    print("  - reproduce proven Stage 3F")
    print("  - reproduce proven Stage 3G")
    print("  - DEVICE_CTRL queries only")
    print("  - NO GET_EMMC_INFO")
    print("  - NO GET_UFS_INFO")
    print("  - NO partition-table query")
    print("  - NO READ_DATA")
    print("  - NO WRITE_DATA")
    print("  - NO FORMAT")
    print("  - NO flash writes")

    # Show exact commands from locally installed MTKClient.
    print()
    print("[Local MTKClient command IDs]")

    for name in (
        "DEVICE_CTRL",
        "GET_DA_VERSION",
        "GET_CHIP_ID",
        "GET_RAM_INFO",
        "GET_PACKET_LENGTH",
        "GET_USB_SPEED",
        "SLA_ENABLED_STATUS",
    ):
        value = getattr(
            cmd,
            name,
        )

        print(
            f"  {name:20s} = "
            f"0x{value:08X}"
        )

    payload = s3e.locate_stage1(
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

        if hwcode != s3f.EXPECTED_HW_CODE:
            raise RuntimeError(
                f"Unexpected HW_CODE "
                f"0x{hwcode:04X}"
            )

        # --------------------------------------------------------
        # Proven 3C + 3E
        # --------------------------------------------------------

        s3f.establish_stage3e(
            ep_out,
            ep_in,
            payload,
        )

        # --------------------------------------------------------
        # Proven 3F
        # --------------------------------------------------------

        print()
        print(
            "[Stage 3F] JUMP_DA"
        )

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
                "Expected DA C0 marker"
            )

        print(
            "  C0 marker: PASS"
        )

        # --------------------------------------------------------
        # Proven 3G
        # --------------------------------------------------------

        s3g.perform_xflash_sync(
            ep_out,
            ep_in,
        )

        # --------------------------------------------------------
        # Stage 3H-A
        # --------------------------------------------------------

        print()
        print("=" * 72)
        print("STAGE 3H-B — eMMC IDENTIFICATION ONLY")
        print("=" * 72)
        print("  command = GET_EMMC_INFO")
        print("  READ_DATA  = DISABLED")
        print("  WRITE_DATA = DISABLED")
        print("  FORMAT     = DISABLED")
        print()

        emmc = devctrl_read(
            ep_out,
            ep_in,
            cmd.GET_EMMC_INFO,
            "GET_EMMC_INFO",
        )

        print_emmc_info(
            emmc
        )

        print()
        print("=" * 72)
        print("STAGE 3H-B SUCCESS")
        print("=" * 72)

        print(
            "eMMC identification query "
            "completed successfully."
        )

        print(
            "GET_EMMC_INFO was the only storage-information command sent."
        )

        print(
            "No partition/flash data was read."
        )

        print(
            "No persistent write was attempted."
        )

        return 0

    except KeyboardInterrupt:
        print()
        print(
            "Interrupted."
        )
        return 130

    except Exception as exc:
        print()
        print("=" * 72)
        print(
            "STAGE 3H-A ABORTED / FAILED CLOSED"
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
                    f"Cleanup warning: "
                    f"{exc}"
                )


if __name__ == "__main__":
    sys.exit(main())
