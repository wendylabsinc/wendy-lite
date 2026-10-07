#!/usr/bin/env python3
"""Read and write the Wendy device configuration partition."""

import argparse
import base64
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
_CERTS_DIR  = os.path.normpath(os.path.join(_REPO_ROOT, "..", "cloud-playground", "certs"))


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


def _split_der_sequence(data: bytes) -> list[bytes]:
    """Split concatenated DER-encoded ASN.1 SEQUENCE objects (e.g. cert chain)."""
    items, offset = [], 0
    while offset < len(data):
        if data[offset] != 0x30 or offset + 2 > len(data):
            break
        b = data[offset + 1]
        if b < 0x80:
            total = 2 + b
        elif b == 0x81:
            if offset + 3 > len(data): break
            total = 3 + data[offset + 2]
        elif b == 0x82:
            if offset + 4 > len(data): break
            total = 4 + (data[offset + 2] << 8 | data[offset + 3])
        else:
            break
        items.append(data[offset : offset + total])
        offset += total
    return items


def _dump_cert(der: bytes, label: str) -> None:
    with tempfile.NamedTemporaryFile(suffix=".der", delete=False) as fh:
        fh.write(der)
        tmp = fh.name
    try:
        r = subprocess.run(
            ["openssl", "x509", "-text", "-noout", "-fingerprint", "-sha256",
             "-inform", "DER", "-in", tmp],
            capture_output=True, text=True,
        )
    finally:
        os.unlink(tmp)

    print(f"\n  {label}:")
    for line in (r.stdout + r.stderr).splitlines():
        print(f"    {line}")


def _dump_key(der: bytes) -> None:
    with tempfile.NamedTemporaryFile(suffix=".der", delete=False) as fh:
        fh.write(der)
        tmp = fh.name
    try:
        r = subprocess.run(
            ["openssl", "pkey", "-text", "-noout", "-inform", "DER", "-in", tmp],
            capture_output=True, text=True,
        )
    finally:
        os.unlink(tmp)

    print("\n  key:")
    for line in (r.stdout + r.stderr).splitlines():
        print(f"    {line}")


def _dump_crypto(prov) -> None:
    printed_header = False

    def header():
        nonlocal printed_header
        if not printed_header:
            print("\nCertificates / Keys:")
            printed_header = True

    if prov.key:
        header()
        try:
            _dump_key(prov.key)
        except Exception as e:
            print(f"\n  key: <failed to decode: {e}>")

    if prov.cert:
        header()
        try:
            _dump_cert(prov.cert, "cert")
        except Exception as e:
            print(f"\n  cert: <failed to decode: {e}>")

    if prov.chain:
        header()
        parts = _split_der_sequence(prov.chain)
        if not parts:
            parts = [prov.chain]
        for i, der in enumerate(parts):
            label = "chain" if len(parts) == 1 else f"chain[{i}]"
            try:
                _dump_cert(der, label)
            except Exception as e:
                print(f"\n  {label}: <failed to decode: {e}>")


def _save_crypto_der(prov, out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)
    written = []

    if prov.key:
        path = os.path.join(out_dir, "key.der")
        with open(path, "wb") as fh:
            fh.write(prov.key)
        written.append(path)

    if prov.cert:
        path = os.path.join(out_dir, "cert.der")
        with open(path, "wb") as fh:
            fh.write(prov.cert)
        written.append(path)

    if prov.chain:
        parts = _split_der_sequence(prov.chain)
        if not parts:
            parts = [prov.chain]

        if len(parts) == 1:
            path = os.path.join(out_dir, "chain.der")
            with open(path, "wb") as fh:
                fh.write(parts[0])
            written.append(path)
        else:
            for i, der in enumerate(parts):
                path = os.path.join(out_dir, f"chain_{i}.der")
                with open(path, "wb") as fh:
                    fh.write(der)
                written.append(path)

    if written:
        print("\nSaved DER files:")
        for path in written:
            print(f"  {path}")
    else:
        print("\nNo provisioning key/cert/chain data found to save.")


def _pem_to_der(path: str) -> bytes:
    """Decode the first PEM block of a file (certificate or PKCS#8 key) to DER."""
    with open(path) as fh:
        lines = fh.read().splitlines()
    try:
        begin = next(i for i, l in enumerate(lines) if l.startswith("-----BEGIN "))
        end   = next(i for i, l in enumerate(lines) if i > begin and l.startswith("-----END "))
    except StopIteration:
        sys.exit(f"{path}: no PEM block found")
    return base64.b64decode("".join(lines[begin + 1 : end]))


def _cert_subject(path: str) -> str:
    r = subprocess.run(
        ["openssl", "x509", "-in", path, "-noout", "-subject"],
        capture_output=True, text=True,
    )
    return r.stdout.strip().removeprefix("subject=") or "<unknown>"


def _build_conf(args, pb2) -> bytes:
    certs = args.certs_dir
    conf  = pb2.WendyConf()

    if args.name:
        conf.device_name = args.name

    if args.ssid:
        net          = conf.wifi.networks.add()
        net.ssid     = args.ssid
        net.password = args.password or ""

    prov            = conf.provisioning
    prov.enrolled   = True
    prov.cloud_host = args.cloud_host
    prov.org_id     = args.org_id
    prov.asset_id   = args.asset_id
    prov.key        = _pem_to_der(os.path.join(certs, "device.key"))
    prov.cert       = _pem_to_der(os.path.join(certs, "device.pem"))
    # The chain is the CA the device verifies the cloud server against; the
    # playground server certificate is self-signed, so it is its own anchor.
    prov.chain      = _pem_to_der(os.path.join(certs, "server.pem"))

    return conf.SerializeToString()


def cmd_read(args):
    part_offset, part_size = _find_conf_partition(args)
    raw = _read_flash(args, part_offset, part_size)

    if len(raw) < HEADER_SIZE:
        sys.exit(f"Only {len(raw)} bytes read, need at least {HEADER_SIZE}")

    magic     = raw[:4]
    body_size = struct.unpack_from("<I", raw, 4)[0]

    print(f"\nHeader:")
    print(f"  magic:     0x{magic.hex()}")
    print(f"  body_size: {body_size} bytes")

    if magic == b"\xff\xff\xff\xff":
        sys.exit("Partition appears erased (magic is all 0xFF)")

    if HEADER_SIZE + body_size > len(raw):
        sys.exit(
            f"body_size {body_size} exceeds available data "
            f"({len(raw) - HEADER_SIZE} bytes after header)"
        )

    body = raw[HEADER_SIZE : HEADER_SIZE + body_size]

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

    prov = conf.provisioning
    if prov.key or prov.cert or prov.chain:
        _dump_crypto(prov)
    if args.save_der_dir:
        _save_crypto_der(prov, args.save_der_dir)


def cmd_write(args):
    certs = args.certs_dir
    for name in ("device.key", "device.pem", "server.pem"):
        if not os.path.isfile(os.path.join(certs, name)):
            sys.exit(f"Missing {os.path.join(certs, name)} (run cloud-playground/gen-certs.sh)")

    pb2   = _load_proto()
    body  = _build_conf(args, pb2)
    image = MAGIC + struct.pack("<I", len(body)) + body

    print("WendyConf:")
    if args.name:
        print(f"  device_name: {args.name}")
    if args.ssid:
        print(f"  wifi ssid:   {args.ssid}")
    print(f"  cloud_host:  {args.cloud_host}")
    print(f"  cert:        {_cert_subject(os.path.join(certs, 'device.pem'))}")
    print(f"  chain:       {_cert_subject(os.path.join(certs, 'server.pem'))}")
    print(f"  body_size:   {len(body)} bytes")

    if args.output:
        with open(args.output, "wb") as fh:
            fh.write(image)
        print(f"\nSaved {len(image)} bytes to {args.output}")
        return

    part_offset, part_size = _find_conf_partition(args)
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
    ap.add_argument(
        "--save-der-dir",
        help="Directory where provisioning key/cert/chain are saved as .der files",
    )
    sub = ap.add_subparsers(dest="command", required=True)
    sub.add_parser("read",  help="Read and decode the conf partition from flash")
    wp = sub.add_parser(
        "write",
        help="Build a cloud provisioning conf from the playground certificates and flash it",
    )
    wp.add_argument(
        "--certs-dir", default=_CERTS_DIR,
        help=f"Directory holding device.key, device.pem and server.pem (default: {_CERTS_DIR})",
    )
    wp.add_argument("--cloud-host", default="localhost",
                    help="Cloud server as host[:port] (default: localhost)")
    wp.add_argument("--org-id",   type=int, default=0, help="Organization ID (default: 0)")
    wp.add_argument("--asset-id", type=int, default=0, help="Asset ID (default: 0)")
    wp.add_argument("--name",     help="Device name")
    wp.add_argument("--ssid",     help="WiFi SSID")
    wp.add_argument("--password", help="WiFi password")
    wp.add_argument("--output", "-o",
                    help="Save the partition image to this file instead of flashing it")
    args = ap.parse_args()
    {"read": cmd_read, "write": cmd_write}[args.command](args)


if __name__ == "__main__":
    main()
