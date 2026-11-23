#!/usr/bin/env python3
"""Download nanopb, populate components/nanopb/ with runtime files, and
regenerate protobuf code from every proto file listed in PROTO_TARGETS.

Usage:
    python tools/update_protobuf.py [--version X.Y.Z]
    python tools/update_protobuf.py --shared-contracts-only
    python tools/update_protobuf.py --check-shared-contracts

Requirements:
  - buf 1.75.0 and protoc 34.0
  - Python protobuf: python -m pip install protobuf==7.34.0
  - protoc-gen-go: go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11
  - protoc-gen-go-grpc (full generation only):
      go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.2
"""

import argparse
import filecmp
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

NANOPB_VERSION_DEFAULT = "0.4.9"
NANOPB_TARBALL = (
    "https://github.com/nanopb/nanopb/archive/refs/tags/{version}.tar.gz"
)

# C runtime files to copy into components/nanopb/
RUNTIME_FILES = [
    "pb.h",
    "pb_common.h", "pb_common.c",
    "pb_encode.h",  "pb_encode.c",
    "pb_decode.h",  "pb_decode.c",
]

# (proto path, output header, output source)
SHARED_PROTO_TARGETS = [
    (
        "wendylite/v1/wendy_com_msg.proto",
        "components/wendy_com/include/wendy_com_msg.pb.h",
        "components/wendy_com/src/wendy_com_msg.pb.c",
    ),
    (
        "wendylite/v1/sensorlink.proto",
        "components/wendy_com/include/sensorlink.pb.h",
        "components/wendy_com/src/sensorlink.pb.c",
    ),
]
PROTO_TARGETS = [
    (
        "components/wendy_conf/proto/wendy_conf.proto",
        "components/wendy_conf/include/wendy_conf.pb.h",
        "components/wendy_conf/src/wendy_conf.pb.c",
    ),
]

# sensorlink.proto is generated on its own, into the package the WendyOS
# project also generates it into, so the console client code shared between the
# two projects can spell these types the same way in both.
SENSORLINK_GO_PKG = (
    "github.com/wendylabsinc/wendy/go/proto/gen/sensorlinkpb;sensorlinkpb"
)

# (proto paths, Go output directory, Go package path, gRPC service stubs,
#  imported protos -> their Go package)
# — paths relative to repo root; protos in one entry must live in the same
# directory and are compiled together (so imports between them resolve).
# The last element names the Go package of protos that are imported but not
# generated here: no code is emitted for them, but protoc-gen-go still has to
# know which package the generated code should import them from.
SHARED_GO_TARGETS = [
    (
        "wendylite/v1",  # Keep the existing WendyCom descriptor filename.
        ["wendy_com_msg.proto"],
        "go/console/wendypb",
        "github.com/wendylabsinc/wendy/go/proto/gen/litepb;litepb",
        False,
        {"wendylite/v1/sensorlink.proto": SENSORLINK_GO_PKG},
    ),
    (
        ".",
        ["wendylite/v1/sensorlink.proto"],
        "go/console/sensorlinkpb",
        SENSORLINK_GO_PKG,
        False,
        {},
    ),
]
GO_TARGETS = [
    (
        ["components/wendy_conf/proto/wendy_conf.proto"],
        "go/console/wendypb",
        "github.com/wendylabsinc/wendy/go/proto/gen/litepb;litepb",
        False,
        {},
    ),
    (
        [
            "go/proto/wendy_com_relay_msg.proto",
            "go/proto/wendy_com_relay_service.proto",
        ],
        "go/wcomrelaypb",
        "github.com/wendylabsinc/wendy/go/proto/gen/wcomrelaypb",
        True,
        {},
    ),
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def repo_root():
    return os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))


def _tar_extractall(tar, path, members):
    """tarfile.extractall() with the 'data' filter on Python 3.12+."""
    kwargs = {"filter": "data"} if sys.version_info >= (3, 12) else {}
    tar.extractall(path=path, members=members, **kwargs)


# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------

def download(version):
    cache_dir = os.path.join(repo_root(), "build")
    cache_path = os.path.join(cache_dir, f"nanopb-{version}.tar.gz")
    if os.path.exists(cache_path):
        print(f"Using cached nanopb {version} ({os.path.relpath(cache_path)}) …")
        with open(cache_path, "rb") as f:
            return io.BytesIO(f.read())
    url = NANOPB_TARBALL.format(version=version)
    print(f"Downloading nanopb {version} …")
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req) as r:
        data = r.read()
    os.makedirs(cache_dir, exist_ok=True)
    with open(cache_path, "wb") as f:
        f.write(data)
    print(f"  Cached → {os.path.relpath(cache_path)}")
    return io.BytesIO(data)


def populate_runtime(buf, version, dest):
    """Copy the handful of C runtime files into components/nanopb/."""
    strip = f"nanopb-{version}/"
    os.makedirs(dest, exist_ok=True)
    buf.seek(0)
    with tarfile.open(fileobj=buf, mode="r:gz") as tar:
        members = []
        for name in RUNTIME_FILES:
            m = tar.getmember(strip + name)
            m.name = name          # drop the top-level directory prefix
            members.append(m)
        _tar_extractall(tar, dest, members)
    rel = os.path.relpath(dest)
    print(f"  Wrote {len(RUNTIME_FILES)} files → {rel}/")


def generate(buf, version, proto_rel, out_h_rel, out_c_rel, root, *, shared_root=None):
    """Extract the nanopb generator from the tarball and run it."""
    strip = f"nanopb-{version}/"

    with tempfile.TemporaryDirectory(prefix="nanopb_gen_") as tmp:
        # Extract just the generator/ subtree
        buf.seek(0)
        with tarfile.open(fileobj=buf, mode="r:gz") as tar:
            members = [m for m in tar.getmembers()
                       if m.name.startswith(strip + "generator/")]
            for m in members:
                m.name = m.name[len(strip):]   # strip top-level dir
            _tar_extractall(tar, tmp, members)

        generator = os.path.join(tmp, "generator", "nanopb_generator.py")
        out_dir   = os.path.join(tmp, "out")
        os.makedirs(out_dir)

        proto_dir = shared_root or os.path.dirname(os.path.join(root, proto_rel))
        proto_name = proto_rel if shared_root else os.path.basename(proto_rel)
        proto_base = os.path.splitext(proto_name)[0]

        # Run from proto_dir so the generator finds <proto_base>.options
        # automatically (it searches for it alongside the proto file).
        cmd = [sys.executable, generator, f"--output-dir={out_dir}"]
        if shared_root:
            cmd += ["--strip-path", "--error-on-unmatched"]
        cmd.append(proto_name)

        print(f"  Generating {proto_base}.pb.{{h,c}} …")
        r = subprocess.run(cmd, capture_output=True, text=True, cwd=proto_dir)

        if r.returncode != 0:
            output = (r.stderr or "") + (r.stdout or "")
            if "protoc" in output or "grpc" in output.lower():
                print(
                    "\nHint: the nanopb generator needs protoc.\n"
                    "  pip install grpcio-tools   # bundles protoc\n"
                    "  brew install protobuf       # system protoc",
                    file=sys.stderr,
                )
            sys.exit(f"Generator failed:\n{output}")

        for suffix, dest in ((".pb.h", out_h_rel), (".pb.c", out_c_rel)):
            output = Path(root, dest)
            output.parent.mkdir(parents=True, exist_ok=True)
            source = Path(out_dir, proto_base + suffix)
            if shared_root:
                # nanopb emits trailing blank lines for every imported descriptor.
                output.write_bytes(source.read_bytes().rstrip(b"\n") + b"\n")
            else:
                shutil.copyfile(source, output)
        print(f"    → {out_h_rel}")
        print(f"    → {out_c_rel}")


def generate_go(proto_rels, out_dir_rel, go_package, grpc, import_pkgs, root, *, proto_root=None, import_root=None):
    """Run protoc with protoc-gen-go (and protoc-gen-go-grpc for services)."""
    proto_names = proto_rels if proto_root else [os.path.basename(p) for p in proto_rels]
    proto_dir = proto_root or os.path.dirname(os.path.join(root, proto_rels[0]))
    out_dir     = os.path.join(root, out_dir_rel)
    os.makedirs(out_dir, exist_ok=True)

    # protoc-gen-go is typically installed in $(go env GOPATH)/bin
    gopath = subprocess.run(
        ["go", "env", "GOPATH"], capture_output=True, text=True
    ).stdout.strip()
    env = os.environ.copy()
    if gopath:
        env["PATH"] = os.path.join(gopath, "bin") + os.pathsep + env.get("PATH", "")

    cmd = [
        "protoc",
        f"--proto_path={proto_dir}",
        f"--go_out={out_dir}",
    ]
    layout = f"module={go_package.split(';')[0]}" if proto_root else "paths=source_relative"
    cmd.append(f"--go_opt={layout}")
    if import_root and import_root != proto_dir:
        cmd.append(f"--proto_path={import_root}")
    cmd += [f"--go_opt=M{name}={go_package}" for name in proto_names]
    cmd += [f"--go_opt=M{name}={pkg}" for name, pkg in import_pkgs.items()]
    if grpc:
        cmd += [
            f"--go-grpc_out={out_dir}",
            f"--go-grpc_opt={layout}",
        ]
        cmd += [f"--go-grpc_opt=M{name}={go_package}" for name in proto_names]
        cmd += [f"--go-grpc_opt=M{name}={pkg}" for name, pkg in import_pkgs.items()]
    cmd += proto_names

    print(f"  Generating Go code from {', '.join(proto_names)} …")
    r = subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=proto_dir)

    if r.returncode != 0:
        output = (r.stderr or "") + (r.stdout or "")
        if "protoc-gen-go" in output:
            print(
                "\nHint: protoc-gen-go / protoc-gen-go-grpc is not installed.\n"
                "  go install google.golang.org/protobuf/cmd/protoc-gen-go@latest\n"
                "  go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest",
                file=sys.stderr,
            )
        sys.exit(f"Go generation failed:\n{output}")

    for name in proto_names:
        base = os.path.splitext(os.path.basename(name))[0]
        print(f"    → {os.path.join(out_dir_rel, base + '.pb.go')}")
        if grpc and os.path.exists(os.path.join(out_dir, base + "_grpc.pb.go")):
            print(f"    → {os.path.join(out_dir_rel, base + '_grpc.pb.go')}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def generate_shared(buf, version, root, *, check):
    with tempfile.TemporaryDirectory(prefix="wendy_shared_protos_") as scratch:
        shared_root = os.path.join(scratch, "protos")
        subprocess.run(
            ["bash", os.path.join(root, "tools/shared-grpc-api-contracts.sh"), "--export", shared_root],
            check=True,
        )
        generated = os.path.join(scratch, "generated")
        outputs = []
        for proto, _, _ in SHARED_PROTO_TARGETS:
            options = os.path.splitext(os.path.basename(proto))[0] + ".options"
            shutil.copyfile(
                os.path.join(root, "components/wendy_com/proto", options),
                os.path.join(shared_root, os.path.dirname(proto), options),
            )
        for proto, header, source in SHARED_PROTO_TARGETS:
            generate(buf, version, proto, header, source, generated, shared_root=shared_root)
            outputs.extend([header, source])
        for proto_dir, protos, out, package, grpc, imports in SHARED_GO_TARGETS:
            generate_go(protos, out, package, grpc, imports, generated,
                        proto_root=str(Path(shared_root, proto_dir)), import_root=shared_root)
            outputs.extend(os.path.join(out, os.path.basename(p).replace(".proto", ".pb.go")) for p in protos)
        if check:
            drift = []
            for path in outputs:
                committed = Path(root, path)
                if not committed.is_file() or not filecmp.cmp(committed, Path(generated, path), shallow=False):
                    drift.append(path)
            if drift:
                sys.exit("Shared protobuf bindings differ. Run python tools/update_protobuf.py "
                         "--shared-contracts-only to regenerate:\n" + "\n".join(drift))
        else:
            for path in outputs:
                dest = Path(root, path)
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(Path(generated, path), dest)


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument(
        "--version", default=NANOPB_VERSION_DEFAULT,
        metavar="X.Y.Z", help=f"nanopb version (default: {NANOPB_VERSION_DEFAULT})",
    )
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--shared-contracts-only", action="store_true")
    mode.add_argument("--check-shared-contracts", action="store_true")
    args = ap.parse_args()

    root = repo_root()
    buf  = download(args.version)

    generate_shared(buf, args.version, root, check=args.check_shared_contracts)
    if args.shared_contracts_only or args.check_shared_contracts:
        return

    print("\n--- Runtime files ---")
    populate_runtime(buf, args.version,
                     os.path.join(root, "components", "nanopb"))

    print("\n--- C code generation ---")
    for proto, out_h, out_c in PROTO_TARGETS:
        generate(buf, args.version, proto, out_h, out_c, root)

    print("\n--- Go code generation ---")
    for protos, out_dir, go_package, grpc, import_pkgs in GO_TARGETS:
        generate_go(protos, out_dir, go_package, grpc, import_pkgs, root)

    print("\nDone. Commit the generated files under components/ and go/.")


if __name__ == "__main__":
    main()
