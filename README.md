# TCL Flip 2 / T408DL Recovery Tool

Experimental recovery and firmware access tooling for the MediaTek MT6739-based
TCL Flip 2 / T408DL.

## Current proven chain

Preloader capture
-> volatile S-USBDL bypass
-> Wiko DA Stage1
-> XFlash synchronization
-> patched Wiko Stage2
-> eMMC READ_DATA / WRITE_DATA
-> GPT guarded writes
-> full SHA256 read-back verification

## Run

    sudo ./t408dl

## Important

Boot0 / Boot1 / RPMB are not currently exposed through the GPT writer.
GPT USER writes should always be followed by complete read-back verification.
