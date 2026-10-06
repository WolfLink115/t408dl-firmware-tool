# t408dl

Experimental recovery, dumping, and low-level flashing utility for the
TCL Flip 2 / T408DL based on the MediaTek MT6739 platform.

This project was developed through reverse engineering and repeated testing
against real T408DL hardware.

> [!CAUTION]
> # THIS SOFTWARE CAN BRICK YOUR PHONE
>
> This tool performs low-level operations against MediaTek Preloader and eMMC
> storage.
>
> One TCL Flip 2 / T408DL was rendered USB-silent and effectively
> unrecoverable during development after incompatible low-level firmware
> components were cross-flashed.
>
> The current implementation contains substantially stronger safeguards,
> including live-GPT validation, exact partition geometry checks, streaming
> reads/writes, and full SHA-256 read-back verification.
>
> Those safeguards reduce risk. They do NOT make flashing risk-free.
>
> DUMP YOUR DEVICE BEFORE WRITING TO IT.
>
> Prefer firmware originating from your own device and exact firmware revision
> whenever possible.
>
> Do not assume firmware from another T408DL revision is interchangeable
> simply because one particular cross-version image worked during testing.
>
> YOU USE THIS SOFTWARE ENTIRELY AT YOUR OWN RISK.
>
> Data loss, boot failure, loss of USB recovery access, and permanent device
> failure are possible.

---

## Status

Experimental / alpha-quality software.

The complete recovery chain has been validated on real TCL Flip 2 / T408DL
hardware.

This project should still be treated as research software rather than a
production flashing utility.

---

## Proven recovery chain

    MediaTek Preloader capture
            |
            v
    READ16 32-bit address wraparound
            |
            v
    low-memory / SRAM observation
            |
            v
    controlled WRITE16 replay
            |
            v
    existing Preloader code-reuse gadget
            |
            v
    S-USBDL state cleared
            |
            v
    compatible Wiko XFlash DA1 accepted
            |
            v
    JUMP_DA
            |
            v
    XFlash synchronization
            |
            v
    patched DA2 execution
            |
            v
    eMMC READ_DATA / WRITE_DATA
            |
            v
    live GPT parsing + CRC validation
            |
            v
    guarded partition operations
            |
            v
    full SHA-256 read-back verification

The security bypass is volatile. It modifies live Preloader state in RAM rather
than permanently patching the Preloader stored on eMMC.

---

## Hardware validation

Successfully tested on real TCL Flip 2 / T408DL hardware.

Confirmed working:

- MediaTek Preloader capture and synchronization
- volatile S-USBDL bypass
- compatible Wiko XFlash DA1 upload
- XFlash synchronization
- patched XFlash DA2 execution
- eMMC identification
- GPT parsing
- GPT header CRC verification
- GPT partition-entry CRC verification
- partition lookup by GPT name
- raw USER-area reads
- streaming partition reads
- streaming large-partition reads
- 2 GiB super partition dump
- eMMC Boot0 read
- eMMC Boot1 read
- conservative Preloader extraction
- guarded USER-area partition writes
- exact partition-size enforcement
- full post-write SHA-256 verification
- successful recovery of a bootlooping handset

### Recovery test device

Observed firmware identity on one successfully recovered handset:

- Physical label: KEEZ
- swversion partition: KEEZ
- Android userspace: KEFS
- Preloader source-tree lineage: vKEFS
- loader_ext source-tree lineage: vKEFS
- replacement boot image obtained from a KEE7 firmware package
- replacement boot image itself contains KEEZ build identification
- device successfully booted Android after the boot partition was replaced

This does NOT prove that arbitrary KEE7/KEEZ/KEFS components are mutually
interchangeable.

---

## Development brick warning

During development, one test handset became completely USB-silent after
cross-flashing incompatible low-level firmware components.

The affected experiment involved low-level firmware including loader_ext and
swversion.

That incident is one reason the current tool deliberately restricts dangerous
operations and validates live storage geometry before writes.

A successful cross-version boot image test does NOT imply that low-level
firmware may safely be cross-flashed.

---

## Requirements

- Linux
- Python 3
- PyUSB
- libusb
- physical USB access to a TCL Flip 2 / T408DL
- required external Download Agent assets

Install Python requirements with:

    python3 -m pip install -r requirements.txt

Depending on your distribution, the system libusb package may also be needed.

---

## External / proprietary assets

This repository does NOT distribute TCL firmware, complete device dumps,
private partitions, or proprietary Wiko/MediaTek Download Agent binaries.

The currently proven chain uses locally supplied compatible Wiko XFlash DA
assets.

The development tree expects these locally under:

    wiko-da/

The proprietary binaries are intentionally excluded from Git.

Do not commit or redistribute:

- TCL firmware packages
- complete device dumps
- Wiko Download Agent binaries
- MediaTek proprietary binaries
- nvram
- nvdata
- nvcfg
- persist
- efuse
- RPMB data
- device-specific calibration/provisioning data

---

## Running

From the project directory:

    ./t408dl

Root may be required depending on USB permissions:

    sudo ./t408dl

A udev rule is preferable to permanently running the tool as root.

---

## Interactive commands

The Stage2 shell exposes commands including:

    info
    partitions
    gpt
    partition-info <name>

    dump <partition> [outfile]
    flash <partition> <image>

    dump-firmware <directory>
    dump-all <directory>

    read-raw <address> <length> <outfile>

    dump-hw boot0 [outfile]
    dump-hw boot1 [outfile]
    dump-preloader [outfile]

    help
    quit

Run help in the interactive shell for the exact commands supported by your
checkout.

---

## GPT-aware partition access

The recommended interface uses GPT partition names rather than manually typed
addresses.

Examples:

    partition-info boot
    dump boot backups/boot.bin

A write can be requested with:

    flash boot firmware/boot.img

Before a GPT partition write is allowed, the tool validates the live primary
GPT and obtains partition geometry from the device itself.

The write path requires:

1. valid GPT signature
2. valid GPT header CRC
3. valid partition-entry-array CRC
4. exact GPT partition-name lookup
5. exact image/partition size agreement
6. an allowed eMMC USER-area destination
7. explicit confirmation
8. complete post-write readback
9. matching SHA-256 hashes

A successful write ends with a result similar to:

    WRITE + FULL READ-BACK VERIFY = PASS

Do not treat a write as successful until verification completes.

---

## Firmware dumping

A firmware-oriented dump can be created with:

    dump-firmware backups/device-name

The tool can automatically preserve applicable firmware partitions, GPT
metadata, hardware boot areas, hashes, and a manifest.

Large partitions such as super are streamed directly to disk rather than
stored entirely in RAM.

Interrupted output is kept separate from completed dumps so a partial image is
not silently mistaken for a complete one.

---

## Full-device dumping

dump-all is more aggressive and can include private or stateful partitions.

These may contain device-specific information such as:

- radio/NVRAM configuration
- provisioning state
- calibration data
- identifiers
- user data

Treat those dumps as private.

Do NOT publish somebody else's full-device dump.

---

## eMMC hardware boot areas

Read-only access is implemented for:

    Linux name       eMMC area       XFlash selector
    ------------------------------------------------
    mmcblk0boot0     BOOT1           1
    mmcblk0boot1     BOOT2           2
    mmcblk0          USER            8

Examples:

    dump-hw boot0 backups/mmcblk0boot0.bin
    dump-hw boot1 backups/mmcblk0boot1.bin

The tool can also conservatively locate and extract a Preloader image from the
boot hardware area:

    dump-preloader backups/preloader_raw.img

Preloader extraction fails closed if the expected MediaTek structures cannot
be identified confidently.

---

## Intentionally unsupported dangerous operations

The following operations are deliberately NOT implemented:

- eMMC Boot0 writes
- eMMC Boot1 writes
- RPMB writes
- FORMAT
- ERASE

Do not bypass these restrictions merely because another operation failed.

Their absence is intentional.

---

## Raw access

An explicit raw USER-area read mode exists for research:

    read-raw <address> <length> <outfile>

Prefer GPT-name-based operations whenever a GPT partition is involved.

---

## Research archive

research/ contains historical scripts, snapshots, experiments, and debugging
material produced while developing the recovery chain.

These are archived research artifacts.

Do not assume scripts under:

    research/legacy-scripts/
    research/snapshots/

have the same safeguards as the current top-level tool.

For normal use, run:

    ./t408dl

---

## Known limitations

- Only a very small number of physical T408DL devices have been tested.
- Firmware-revision compatibility is not fully mapped.
- Cross-version flashing can be dangerous.
- Proprietary DA assets are currently required locally.
- Boot0/Boot1 are read-only.
- RPMB writes are unavailable.
- FORMAT and ERASE are unavailable.
- A successful Preloader exploit does not guarantee that every firmware image
  is compatible with a particular handset.

---

## Recovery philosophy

The project follows a fail-closed approach where practical:

- validate before writing
- derive geometry from the live device
- require exact partition-size matches
- preserve original dumps
- avoid silent overwrite of existing dumps
- stream large data rather than buffering it in RAM
- verify writes with complete readback and SHA-256 comparison
- keep dangerous eMMC hardware-area writes disabled

If the tool cannot establish the assumptions required for a destructive
operation, it should refuse the operation rather than guess.

---

## Credits

Project direction, hardware research, real-device testing, dumps, validation,
and reverse-engineering data:

WolfLink115

Implementation assistance, code generation, debugging assistance, protocol
analysis, and documentation:

OpenAI ChatGPT (GPT-5.6 Sol)

The project was developed iteratively against real TCL Flip 2 / T408DL
hardware.

---

## Disclaimer

This project is provided for research, recovery, interoperability, and
educational purposes.

No warranty is provided.

The authors and contributors are not responsible for damaged hardware, lost
data, inaccessible devices, loss of cellular functionality, or any other
consequence resulting from use of this software.

If you use the flashing functionality, you accept the possibility that the
device may never boot or enumerate over USB again.

---

## License

This project is licensed under the GNU General Public License v3.

See `LICENSE` for the full license text.

Parts of the implementation and protocol research were informed by prior work
in the MediaTek reverse-engineering ecosystem, including MTKClient.
