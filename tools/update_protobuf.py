#!/usr/bin/env python3
"""Download nanopb, populate components/nanopb/ with runtime files, and
regenerate protobuf code from every proto file listed in PROTO_TARGETS.

Usage:
    python tools/update_protobuf.py [--version X.Y.Z]

Requirements:
  - protoc:         brew install protobuf  OR  pip install grpcio-tools
  - protoc-gen-go:  go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
"""

import argparse
import io
import os
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

# (proto path, output header, output source)  — all relative to repo root
PROTO_TARGETS = [
    (
        "components/wendy_com/proto/wendy_com_msg.proto",
        "components/wendy_com/include/wendy_com_msg.pb.h",
        "components/wendy_com/src/wendy_com_msg.pb.c",
    ),
    (
        "components/wendy_conf/proto/wendy_conf.proto",
        "components/wendy_conf/include/wendy_conf.pb.h",
        "components/wendy_conf/src/wendy_conf.pb.c",
    ),
]

# (proto paths, Go output directory, Go package path, gRPC service stubs)
# — paths relative to repo root; protos in one entry must live in the same
# directory and are compiled together (so imports between them resolve)
GO_TARGETS = [
    (
        ["components/wendy_com/proto/wendy_com_msg.proto"],
        "go/console/wendypb",
        "wendy-console/wendypb",
        False,
    ),
    (
        ["components/wendy_conf/proto/wendy_conf.proto"],
        "go/console/wendypb",
        "wendy-console/wendypb",
        False,
    ),
    (
        [
            "go/proto/wendy_com_tunnel_msg.proto",
            "go/proto/wendy_com_tunnel_service.proto",
        ],
        "go/tunnelpb",
        "github.com/wendylabsinc/wendy/go/proto/gen/tunnelpb",
        True,
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


def generate(buf, version, proto_rel, out_h_rel, out_c_rel, root):
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

        proto_abs  = os.path.join(root, proto_rel)
        proto_dir  = os.path.dirname(proto_abs)
        proto_base = os.path.splitext(os.path.basename(proto_abs))[0]

        # Run from proto_dir so the generator finds <proto_base>.options
        # automatically (it searches for it alongside the proto file).
        cmd = [sys.executable, generator,
               f"--output-dir={out_dir}",
               os.path.basename(proto_abs)]

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

        shutil.copy(os.path.join(out_dir, proto_base + ".pb.h"),
                    os.path.join(root, out_h_rel))
        shutil.copy(os.path.join(out_dir, proto_base + ".pb.c"),
                    os.path.join(root, out_c_rel))
        print(f"    → {out_h_rel}")
        print(f"    → {out_c_rel}")


def generate_go(proto_rels, out_dir_rel, go_package, grpc, root):
    """Run protoc with protoc-gen-go (and protoc-gen-go-grpc for services)."""
    proto_names = [os.path.basename(p) for p in proto_rels]
    proto_dir   = os.path.dirname(os.path.join(root, proto_rels[0]))
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
        "--go_opt=paths=source_relative",
    ]
    cmd += [f"--go_opt=M{name}={go_package}" for name in proto_names]
    if grpc:
        cmd += [
            f"--go-grpc_out={out_dir}",
            "--go-grpc_opt=paths=source_relative",
        ]
        cmd += [f"--go-grpc_opt=M{name}={go_package}" for name in proto_names]
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
        base = os.path.splitext(name)[0]
        print(f"    → {os.path.join(out_dir_rel, base + '.pb.go')}")
        if grpc and os.path.exists(os.path.join(out_dir, base + "_grpc.pb.go")):
            print(f"    → {os.path.join(out_dir_rel, base + '_grpc.pb.go')}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument(
        "--version", default=NANOPB_VERSION_DEFAULT,
        metavar="X.Y.Z", help=f"nanopb version (default: {NANOPB_VERSION_DEFAULT})",
    )
    args = ap.parse_args()

    root = repo_root()
    buf  = download(args.version)

    print("\n--- Runtime files ---")
    populate_runtime(buf, args.version,
                     os.path.join(root, "components", "nanopb"))

    print("\n--- C code generation ---")
    for proto, out_h, out_c in PROTO_TARGETS:
        generate(buf, args.version, proto, out_h, out_c, root)

    print("\n--- Go code generation ---")
    for protos, out_dir, go_package, grpc in GO_TARGETS:
        generate_go(protos, out_dir, go_package, grpc, root)

    print("\nDone. Commit the generated files under components/ and go/.")


if __name__ == "__main__":
    main()
