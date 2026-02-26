#!/usr/bin/env python3
"""
wendy_serve.py — Serve a WASM binary to Wendy devices over WiFi.

Usage:
    python wendy_serve.py path/to/app.wasm          # Serve WASM + broadcast
    python wendy_serve.py --reload                   # Send UDP reload broadcast
    python wendy_serve.py path/to/app.wasm --port 8080  # Custom port

Requires: zeroconf (pip install zeroconf) for reliable unicast delivery.
Without it, falls back to broadcast which may be blocked by AP isolation.
"""

import argparse
import http.server
import ipaddress
import os
import socket
import sys
import threading
import time


def get_local_ip():
    """Get the local IP address used for LAN communication."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def get_broadcast_address():
    """Get the subnet broadcast address for the local network."""
    local_ip = get_local_ip()
    # Assume /24 subnet — covers most home/office networks
    net = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
    return str(net.broadcast_address)


def send_reload(udp_port, http_host, http_port, device_ips=None):
    """Send a WENDY_RELOAD UDP packet to devices.

    Sends unicast to each discovered device IP first (most reliable),
    then directed broadcast and limited broadcast as fallbacks.
    """
    payload = f"WENDY_RELOAD {http_host}:{http_port}".encode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    # Unicast to each discovered device (bypasses AP isolation)
    for ip in (device_ips or []):
        sock.sendto(payload, (ip, udp_port))
        print(f"Sent unicast '{payload.decode()}' to {ip}:{udp_port}")

    # Subnet broadcast as fallback
    broadcast_addr = get_broadcast_address()
    sock.sendto(payload, (broadcast_addr, udp_port))
    print(f"Sent broadcast '{payload.decode()}' to {broadcast_addr}:{udp_port}")

    sock.close()


def discover_devices(timeout=2):
    """Discover Wendy devices on the network via mDNS.

    Returns a list of (hostname, ip) tuples for discovered devices.
    """
    try:
        from zeroconf import ServiceBrowser, Zeroconf
    except ImportError:
        print("Warning: zeroconf not installed — cannot discover devices.")
        print("  Install with: pip install zeroconf")
        return []

    devices = []  # list of (hostname, ip)

    class Listener:
        def add_service(self, zc, type_, name):
            info = zc.get_service_info(type_, name)
            if info:
                for addr_bytes in info.addresses:
                    ip = socket.inet_ntoa(addr_bytes)
                    hostname = info.server.rstrip(".")
                    devices.append((hostname, ip))
                    print(f"  Found device: {hostname} at {ip}")

        def remove_service(self, zc, type_, name):
            pass

        def update_service(self, zc, type_, name):
            pass

    zc = Zeroconf()
    listener = Listener()
    browser = ServiceBrowser(zc, "_wendy._tcp.local.", listener)
    print(f"Discovering Wendy devices ({timeout}s)...")
    time.sleep(timeout)
    browser.cancel()
    zc.close()
    return devices


def select_devices(devices):
    """Show an interactive menu to select target devices.

    Returns a list of IP address strings.
    """
    if not sys.stdin.isatty():
        # Non-interactive: use all discovered devices
        return [ip for _, ip in devices]

    if not devices:
        print("\nNo devices found via mDNS.")
        manual = input("Enter device IP (or press Enter to broadcast only): ").strip()
        return [manual] if manual else []

    # Deduplicate by IP, preserving order
    seen = set()
    unique = []
    for hostname, ip in devices:
        if ip not in seen:
            seen.add(ip)
            unique.append((hostname, ip))

    if len(unique) == 1:
        print(f"\nUsing device: {unique[0][0]} ({unique[0][1]})")
        return [unique[0][1]]

    print("\nDiscovered devices:")
    for i, (hostname, ip) in enumerate(unique, 1):
        print(f"  {i}) {hostname} ({ip})")
    print(f"  a) All devices")
    print(f"  m) Enter IP manually")

    choice = input("Select device [1]: ").strip().lower()

    if choice == "a":
        return [ip for _, ip in unique]
    if choice == "m":
        manual = input("Enter device IP: ").strip()
        return [manual] if manual else []
    if choice == "":
        choice = "1"

    try:
        idx = int(choice) - 1
        if 0 <= idx < len(unique):
            return [unique[idx][1]]
    except ValueError:
        pass

    print(f"Invalid choice, using all devices")
    return [ip for _, ip in unique]


class ReuseAddrHTTPServer(http.server.HTTPServer):
    allow_reuse_address = True


class WasmHandler(http.server.BaseHTTPRequestHandler):
    """Serves a single WASM file at /app.wasm, then shuts down."""

    wasm_path = None
    server_ref = None  # set before serving

    def do_GET(self):
        if self.path == "/app.wasm":
            try:
                with open(self.wasm_path, "rb") as f:
                    data = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "application/wasm")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                print(f"Served {self.wasm_path} ({len(data)} bytes)")
                # Shut down after first successful download
                threading.Thread(target=self.server_ref.shutdown, daemon=True).start()
            except FileNotFoundError:
                self.send_error(404, "WASM file not found")
        else:
            self.send_error(404, "Not found")

    def log_message(self, format, *args):
        # Suppress default HTTP request logging
        pass


def serve_wasm(wasm_path, port, udp_port, auto_reload=False, device_ips=None):
    """Start HTTP server and broadcast reload to devices."""
    if not os.path.isfile(wasm_path):
        print(f"Error: '{wasm_path}' not found", file=sys.stderr)
        sys.exit(1)

    local_ip = get_local_ip()

    # Bind HTTP server first (port 0 = OS picks a free port)
    WasmHandler.wasm_path = wasm_path
    httpd = ReuseAddrHTTPServer(("0.0.0.0", port), WasmHandler)
    WasmHandler.server_ref = httpd
    actual_port = httpd.server_address[1]

    print(f"Serving '{wasm_path}' at http://{local_ip}:{actual_port}/app.wasm")
    print(f"Press Ctrl+C to stop")

    # Send reload broadcast after server is up, so devices download the binary
    if auto_reload:
        def delayed_reload():
            time.sleep(1)
            send_reload(udp_port, local_ip, actual_port, device_ips=device_ips)
        threading.Thread(target=delayed_reload, daemon=True).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        httpd.server_close()


def main():
    parser = argparse.ArgumentParser(
        description="Serve WASM binaries to Wendy devices over WiFi"
    )
    parser.add_argument(
        "wasm_file",
        nargs="?",
        help="Path to the .wasm file to serve",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=0,
        help="HTTP server port (default: 0 = auto-assign)",
    )
    parser.add_argument(
        "--udp-port",
        type=int,
        default=4210,
        help="UDP reload broadcast port (default: 4210)",
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Send a WENDY_RELOAD UDP broadcast (if no wasm_file, just send and exit)",
    )
    parser.add_argument(
        "--device",
        action="append",
        default=[],
        help="Device IP address (repeatable, skips mDNS discovery)",
    )

    args = parser.parse_args()

    if args.device:
        device_ips = args.device
    else:
        devices = discover_devices()
        device_ips = select_devices(devices)

    if args.reload and not args.wasm_file:
        local_ip = get_local_ip()
        send_reload(args.udp_port, local_ip, args.port if args.port else 0, device_ips=device_ips)
        return

    if not args.wasm_file:
        parser.error("wasm_file is required unless --reload is specified")

    serve_wasm(args.wasm_file, args.port, args.udp_port, auto_reload=args.reload, device_ips=device_ips)


if __name__ == "__main__":
    main()
