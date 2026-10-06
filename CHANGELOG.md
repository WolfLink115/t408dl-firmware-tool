# Changelog

## v0.1.0-alpha

First hardware-validated experimental release.

### Proven recovery chain

- MediaTek Preloader capture and synchronization
- READ16 address-wraparound primitive
- controlled volatile S-USBDL bypass
- compatible Wiko XFlash DA1 execution
- XFlash synchronization
- patched DA2 execution
- eMMC READ_DATA
- eMMC WRITE_DATA

### Storage support

- live GPT parsing
- GPT header CRC verification
- GPT partition-entry CRC verification
- partition lookup by GPT name
- streaming partition reads
- streaming large-partition dumps
- raw USER-area reads
- firmware-oriented automated dumps
- full-device dump mode
- manifest generation
- SHA-256 generation

### Hardware-area support

- read-only eMMC Boot0 dumping
- read-only eMMC Boot1 dumping
- conservative Preloader extraction

Boot0, Boot1, and RPMB writes remain intentionally disabled.

### Flashing safeguards

- live GPT geometry validation
- exact partition-size requirements
- explicit confirmation
- USER-area GPT partition restriction
- full post-write readback
- SHA-256 source/readback comparison
- collision-safe dump filenames

FORMAT and ERASE remain intentionally unimplemented.

### Real-device validation

Validated on real TCL Flip 2 / T408DL hardware.

A complete firmware-oriented dump was successfully produced, including:

- GPT
- firmware partitions
- 2 GiB super partition
- eMMC Boot0
- eMMC Boot1
- extracted Preloader

A bootlooping handset was subsequently recovered by writing a compatible boot
image through the GPT-aware flash command and verifying the complete partition
by SHA-256 readback.

### Important warning

One development handset was rendered USB-silent and effectively unrecoverable
during earlier low-level cross-flashing experiments.

This release should be considered experimental.
