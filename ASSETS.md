# External Assets

`t408dl` does not distribute proprietary TCL, MediaTek, or Wiko firmware or
Download Agent binaries.

Some functionality requires compatible external assets to be supplied locally
by the user.

## Download Agent assets

The currently proven recovery chain uses compatible Wiko XFlash Download Agent
components stored locally under:

    wiko-da/

These files are intentionally excluded from Git.

Do not commit proprietary DA binaries to this repository.

## Firmware

Firmware used for recovery or testing should be stored locally under:

    firmware/

Firmware files are intentionally excluded from Git.

Whenever possible, prefer a dump originating from the exact device being
recovered.

Do not assume firmware from another T408DL revision is interchangeable merely
because a particular cross-version image has worked during testing.

## Stock Preloader reference

Development builds may use a known stock Preloader reference under:

    ota/stock/

This directory is intentionally excluded from Git.

## Device dumps

Device dumps are stored under:

    backups/

This directory is intentionally excluded from Git.

Full dumps may contain:

- device identifiers
- NVRAM
- cellular provisioning
- calibration information
- user data
- security state
- persistent configuration

Do not publish somebody else's complete device dump.

## Repository policy

The public repository should contain source code, documentation, tests, and
non-proprietary research material only.

Issues or pull requests containing proprietary firmware, Download Agents, or
private device dumps should not be submitted.
