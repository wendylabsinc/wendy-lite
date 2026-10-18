#!/usr/bin/env python3
"""Read device configuration and update its name or Wi-Fi settings.

Enroll a device with `wendy cloud enroll-device`.
"""

import argparse
import importlib
import json
import os
import struct
import subprocess
import sys
import tempfile

MAGIC             = b"WYC0"
HEADER_SIZE       = 8
PART_TABLE_OFFSET = 0x8000
PART_TABLE_SIZE   = 0xC00
PART_ENTRY_MAGIC  = b"\xaa\x50"
PART_ENTRY_FMT    = "<2sBBII16sI"
CONF_PART_LABEL   = "wendy_conf"

_REPO_ROOT  = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
_PROTO_FILE = os.path.join(_REPO_ROOT, "components", "wendy_conf", "proto", "wendy_conf.proto")


def _load_proto():
    proto_dir  = os.path.dirname(os.path.realpath(_PROTO_FILE))
    proto_base = os.path.basename(_PROTO_FILE)
    mod_name   = os.path.splitext(proto_base)[0] + "_pb2"

    tmp = tempfile.mkdtemp(prefix="wendy_conf_pb_")
    try:
        from grpc_tools import protoc as _grpc_protoc
        rc = _grpc_protoc.main([
            "grpc_tools.protoc",
            f"--proto_path={proto_dir}",
            f"--python_out={tmp}",
            proto_base,
        ])
        if rc:
            sys.exit("grpc_tools.protoc failed")
    except ImportError:
        r = subprocess.run(
            ["protoc", f"--proto_path={proto_dir}", f"--python_out={tmp}", proto_base],
            capture_output=True, text=True,
        )
        if r.returncode:
            sys.exit(
                f"protoc failed:\n{r.stderr.strip()}\n"
                "Install: brew install protobuf  or  pip install grpcio-tools"
            )

    sys.path.insert(0, tmp)
    mod = importlib.import_module(mod_name)
    sys.path.pop(0)
    return mod


def _esptool_cmd(args) -> list[str]:
    cmd = ["esptool.py"]
    if args.port:
        cmd += ["--port", args.port]
    if args.chip != "auto":
        cmd += ["--chip", args.chip]
    return cmd


def _read_flash(args, offset: int, size: int) -> bytes:
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as fh:
        tmp_bin = fh.name

    try:
        print(f"Reading {hex(size)} bytes from {hex(offset)} …", flush=True)
        r = subprocess.run(_esptool_cmd(args) + ["read_flash", hex(offset), hex(size), tmp_bin])
        if r.returncode:
            sys.exit("esptool failed")

        with open(tmp_bin, "rb") as fh:
            return fh.read()
    finally:
        os.unlink(tmp_bin)


def _find_conf_partition(args) -> tuple[int, int]:
    """Locate the conf partition in the partition table stored on the device.

    Its offset differs between partition layouts, so it is never assumed.
    """
    table      = _read_flash(args, PART_TABLE_OFFSET, PART_TABLE_SIZE)
    entry_size = struct.calcsize(PART_ENTRY_FMT)
    for pos in range(0, len(table) - entry_size + 1, entry_size):
        magic, _, _, offset, size, label, _ = struct.unpack_from(PART_ENTRY_FMT, table, pos)
        # The entries end at the MD5 entry or the erased padding.
        if magic != PART_ENTRY_MAGIC:
            break
        if label.rstrip(b"\0") == CONF_PART_LABEL.encode():
            print(f"Partition {CONF_PART_LABEL}: offset {hex(offset)}, size {hex(size)}")
            return offset, size
    sys.exit(f"No '{CONF_PART_LABEL}' partition in the device partition table")


def _build_conf(args, pb2, existing: bytes = b"") -> bytes:
    conf = pb2.WendyConf()
    conf.ParseFromString(existing)

    if args.name is not None:
        conf.device_name = args.name

    if args.ssid is not None:
        conf.ClearField("wifi")
        net          = conf.wifi.networks.add()
        net.ssid     = args.ssid
        net.password = args.password or ""

    return conf.SerializeToString()


def _conf_body(raw: bytes) -> bytes:
    if len(raw) < HEADER_SIZE:
        sys.exit(f"Only {len(raw)} bytes read, need at least {HEADER_SIZE}")
    if raw[:4] == b"\xff\xff\xff\xff":
        return b""
    if raw[:4] != MAGIC:
        sys.exit(f"Invalid configuration magic: 0x{raw[:4].hex()}")
    body_size = struct.unpack_from("<I", raw, 4)[0]
    if HEADER_SIZE + body_size > len(raw):
        sys.exit(
            f"body_size {body_size} exceeds available data "
            f"({len(raw) - HEADER_SIZE} bytes after header)"
        )
    return raw[HEADER_SIZE : HEADER_SIZE + body_size]


def cmd_read(args):
    part_offset, part_size = _find_conf_partition(args)
    raw = _read_flash(args, part_offset, part_size)

    body = _conf_body(raw)

    print(f"\nHeader:")
    print(f"  magic:     0x{raw[:4].hex()}")
    print(f"  body_size: {len(body)} bytes")

    if raw[:4] == b"\xff\xff\xff\xff":
        sys.exit("Partition appears erased (magic is all 0xFF)")

    pb2  = _load_proto()
    conf = pb2.WendyConf()
    conf.ParseFromString(body)

    from google.protobuf import json_format
    d = json_format.MessageToDict(
        conf,
        preserving_proto_field_name=True,
        always_print_fields_with_no_presence=False,
    )
    print("\nWendyConf:")
    print(json.dumps(d, indent=2))


def cmd_write(args):
    if args.name is None and args.ssid is None:
        sys.exit("Provide --name or --ssid. Use `wendy cloud enroll-device` for enrollment.")
    if args.password is not None and args.ssid is None:
        sys.exit("--password requires --ssid")

    existing = b""
    if not args.output:
        part_offset, part_size = _find_conf_partition(args)
        existing = _conf_body(_read_flash(args, part_offset, part_size))

    pb2 = _load_proto()
    body = _build_conf(args, pb2, existing)
    image = MAGIC + struct.pack("<I", len(body)) + body

    print("WendyConf:")
    if args.name:
        print(f"  device_name: {args.name}")
    if args.ssid:
        print(f"  wifi ssid:   {args.ssid}")
    print(f"  body_size:   {len(body)} bytes")

    if args.output:
        with open(args.output, "wb") as fh:
            fh.write(image)
        print(f"\nSaved {len(image)} bytes to {args.output}")
        return

    if len(image) > part_size:
        sys.exit(f"Image is {len(image)} bytes, the partition holds only {part_size}")
    # Fill the whole partition so no byte of the previous conf survives.
    image += b"\xff" * (part_size - len(image))

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as fh:
        fh.write(image)
        tmp_bin = fh.name

    try:
        print(f"Writing {hex(part_size)} bytes to {hex(part_offset)} …", flush=True)
        r = subprocess.run(_esptool_cmd(args) + ["write_flash", hex(part_offset), tmp_bin])
        if r.returncode:
            sys.exit("esptool failed")
    finally:
        os.unlink(tmp_bin)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", "-p", help="Serial port (e.g. /dev/ttyUSB0)")
    ap.add_argument("--chip", "-c", default="auto", help="ESP chip type (default: auto)")
    sub = ap.add_subparsers(dest="command", required=True)
    sub.add_parser("read",  help="Read and decode the conf partition from flash")
    wp = sub.add_parser(
        "write",
        help="Update name or Wi-Fi settings while preserving other stored configuration",
    )
    wp.add_argument("--name",     help="Device name")
    wp.add_argument("--ssid",     help="WiFi SSID")
    wp.add_argument("--password", help="WiFi password")
    wp.add_argument("--output", "-o",
                    help="Create a new name/Wi-Fi partition image instead of updating a device")
    args = ap.parse_args()
    {"read": cmd_read, "write": cmd_write}[args.command](args)


if __name__ == "__main__":
    main()
