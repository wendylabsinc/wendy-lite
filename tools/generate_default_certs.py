#!/usr/bin/env python3
"""Generate a self-signed EC P-256 certificate and private key in DER format.

Output files (relative to repo root):
  components/wendy_server/certs/default_cert.der
  components/wendy_server/certs/default_key.der

These files are embedded at compile time via EMBED_FILES in the wendy_server
CMakeLists.txt and exposed as:
  _binary_default_cert_der_start / _binary_default_cert_der_end
  _binary_default_key_der_start  / _binary_default_key_der_end

Requirements:
  openssl (available on macOS and most Linux distributions)
"""

import os
import subprocess
import sys
import tempfile


def repo_root():
    return os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))


def run(cmd):
    result = subprocess.run(cmd, capture_output=True)
    if result.returncode != 0:
        sys.exit(f"Command failed: {' '.join(cmd)}\n{result.stderr.decode()}")


def main():
    root    = repo_root()
    out_dir = os.path.join(root, "components", "wendy_server", "certs")
    os.makedirs(out_dir, exist_ok=True)

    cert_der = os.path.join(out_dir, "default_cert.der")
    key_der  = os.path.join(out_dir, "default_key.der")

    with tempfile.TemporaryDirectory(prefix="wendy_certs_") as tmp:
        key_pem  = os.path.join(tmp, "key.pem")
        cert_pem = os.path.join(tmp, "cert.pem")

        # EC P-256 key + self-signed certificate valid for 10 years
        run([
            "openssl", "req", "-x509",
            "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-keyout", key_pem,
            "-out",    cert_pem,
            "-days",   "3650",
            "-nodes",
            "-subj",   "/CN=wendy-lite-default",
        ])

        # Certificate → DER
        run(["openssl", "x509", "-in", cert_pem, "-out", cert_der, "-outform", "DER"])

        # Private key → DER (PKCS#8, unencrypted)
        run(["openssl", "pkcs8", "-topk8", "-nocrypt",
             "-in", key_pem, "-out", key_der, "-outform", "DER"])

    print(f"  → {os.path.relpath(cert_der)}")
    print(f"  → {os.path.relpath(key_der)}")
    print("Done.")


if __name__ == "__main__":
    main()
