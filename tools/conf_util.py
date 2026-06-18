#!/usr/bin/env python3
"""Read and write the Wendy device configuration partition."""

import argparse
import importlib
import json
import os
import struct
import subprocess
import sys
import tempfile

PARTITION_OFFSET = 0x3F0000
PARTITION_SIZE   = 0x4000
HEADER_SIZE      = 8

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


def cmd_read(args):
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as fh:
        tmp_bin = fh.name

    try:
        esptool = ["esptool.py"]
        if args.port:
            esptool += ["--port", args.port]
        if args.chip != "auto":
            esptool += ["--chip", args.chip]
        esptool += ["read_flash", hex(PARTITION_OFFSET), hex(PARTITION_SIZE), tmp_bin]

        print(f"Reading {hex(PARTITION_SIZE)} bytes from {hex(PARTITION_OFFSET)} …", flush=True)
        r = subprocess.run(esptool)
        if r.returncode:
            sys.exit("esptool failed")

        with open(tmp_bin, "rb") as fh:
            raw = fh.read()
    finally:
        os.unlink(tmp_bin)

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
    print("write: not implemented yet")


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
    sub.add_parser("write", help="Write the conf partition (not implemented)")
    args = ap.parse_args()
    {"read": cmd_read, "write": cmd_write}[args.command](args)


if __name__ == "__main__":
    main()
