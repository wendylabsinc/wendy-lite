"""Normal RFC3161 interop for arbitrary 32-byte random nonce values."""
import pathlib
import subprocess
import sys
import tempfile

go, generator, verifier = sys.argv[1:]
cases = {
    "low": bytes(range(1, 33)),
    "high": b"\x80" + bytes(range(1, 32)),
    "ff": b"\xff" * 32,
    "zero-prefix-low": b"\0\x01" + bytes(range(2, 32)),
    "zero-prefix-high": b"\0\x80" + bytes(range(2, 32)),
    "many-zero": bytes(31) + b"\x01",
    "zero": bytes(32),
}
with tempfile.TemporaryDirectory(prefix="wendy-normal-time-") as directory:
    paths = []
    for name, nonce in cases.items():
        path = str(pathlib.Path(directory) / name)
        subprocess.run([go, "run", generator, path, nonce.hex()], check=True, timeout=30)
        paths.append(path)
    subprocess.run([verifier, *paths], check=True, timeout=30)
