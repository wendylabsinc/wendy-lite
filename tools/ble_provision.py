#!/usr/bin/env python3
"""Provision WiFi credentials to a Wendy device over BLE."""

import argparse
import asyncio
from bleak import BleakClient, BleakScanner

# GATT UUIDs (must match wendy_ble_prov.c)
SVC_UUID     = "00004e57-454e-4459-0001-000000000000"
SSID_UUID    = "00004e57-454e-4459-0001-000100000000"
PASS_UUID    = "00004e57-454e-4459-0001-000200000000"
CMD_UUID     = "00004e57-454e-4459-0001-000300000000"
STATUS_UUID  = "00004e57-454e-4459-0001-000400000000"
DEVNAME_UUID = "00004e57-454e-4459-0001-000500000000"

STATUS_NAMES = {0: "no_creds", 1: "connecting", 2: "connected", 3: "failed"}

CMD_CONNECT = 0x01
CMD_CLEAR   = 0x02


def parse_status(data: bytearray) -> tuple[int, str]:
    code = data[0]
    ip = data[1:].decode("utf-8", errors="replace") if len(data) > 1 else ""
    return code, ip


async def find_device(name_or_addr: str, timeout: float = 10.0):
    """Find a Wendy device by name (e.g. 'Wendy-A3F2') or address.
    On macOS, CoreBluetooth uses UUIDs, not MAC addresses, so we
    always scan and match by name or address."""
    print(f"Scanning for '{name_or_addr}'...")
    devices = await BleakScanner.discover(timeout=timeout)
    for d in devices:
        if d.address == name_or_addr:
            return d
        if d.name and d.name == name_or_addr:
            return d
        # Partial match: allow just "A3F2" to match "Wendy-A3F2"
        if d.name and name_or_addr in d.name:
            return d
    return None


async def scan(prefix: str, timeout: float):
    print(f"Scanning for BLE devices with prefix '{prefix}'...")
    devices = await BleakScanner.discover(timeout=timeout)
    found = []
    for d in devices:
        name = d.name or ""
        if name.startswith(prefix):
            found.append(d)
            print(f"  {name}  ({d.address})")
    if not found:
        print("No Wendy devices found.")
    return found


async def provision(device_id: str, ssid: str, password: str):
    device = await find_device(device_id)
    if not device:
        print(f"Device '{device_id}' not found. Run 'scan' first.")
        return False

    print(f"Connecting to {device.name} ({device.address})...")
    async with BleakClient(device) as client:
        print("Connected.")

        # Read device name
        devname = await client.read_gatt_char(DEVNAME_UUID)
        print(f"Device: {devname.decode()}")

        # Read current status
        raw = await client.read_gatt_char(STATUS_UUID)
        code, ip = parse_status(raw)
        print(f"Current status: {STATUS_NAMES.get(code, code)} {ip}")

        # Subscribe to status notifications
        status_event = asyncio.Event()
        final_status = [None]

        def on_status(_, data: bytearray):
            code, ip = parse_status(data)
            name = STATUS_NAMES.get(code, str(code))
            print(f"  Status: {name} {ip}")
            if code in (2, 3):  # connected or failed
                final_status[0] = (code, ip)
                status_event.set()

        await client.start_notify(STATUS_UUID, on_status)

        # Write credentials
        print(f"Writing SSID: '{ssid}'")
        await client.write_gatt_char(SSID_UUID, ssid.encode("utf-8"))

        print("Writing password")
        await client.write_gatt_char(PASS_UUID, password.encode("utf-8"))

        # Send connect command
        print("Sending connect command...")
        await client.write_gatt_char(CMD_UUID, bytes([CMD_CONNECT]))

        # Wait for result
        try:
            await asyncio.wait_for(status_event.wait(), timeout=30)
        except asyncio.TimeoutError:
            print("Timed out waiting for connection result.")
            return False

        code, ip = final_status[0]
        if code == 2:
            print(f"WiFi connected! IP: {ip}")
            return True
        else:
            print("WiFi connection failed.")
            return False


async def clear_creds(device_id: str):
    device = await find_device(device_id)
    if not device:
        print(f"Device '{device_id}' not found. Run 'scan' first.")
        return

    print(f"Connecting to {device.name} ({device.address})...")
    async with BleakClient(device) as client:
        print("Sending clear credentials command...")
        await client.write_gatt_char(CMD_UUID, bytes([CMD_CLEAR]))
        print("Credentials cleared.")


async def main():
    parser = argparse.ArgumentParser(description="Wendy BLE WiFi provisioning")
    sub = parser.add_subparsers(dest="command")

    # scan
    scan_p = sub.add_parser("scan", help="Scan for Wendy devices")
    scan_p.add_argument("--prefix", default="Wendy", help="Device name prefix")
    scan_p.add_argument("--timeout", type=float, default=5.0)

    # provision
    prov_p = sub.add_parser("provision", help="Set WiFi credentials")
    prov_p.add_argument("device", help="Device name (e.g. 'Wendy-A3F2')")
    prov_p.add_argument("--ssid", required=True)
    prov_p.add_argument("--password", default="")

    # clear
    clear_p = sub.add_parser("clear", help="Clear saved WiFi credentials")
    clear_p.add_argument("device", help="Device name (e.g. 'Wendy-A3F2')")

    args = parser.parse_args()

    if args.command == "scan":
        await scan(args.prefix, args.timeout)
    elif args.command == "provision":
        await provision(args.device, args.ssid, args.password)
    elif args.command == "clear":
        await clear_creds(args.device)
    else:
        parser.print_help()


if __name__ == "__main__":
    asyncio.run(main())
