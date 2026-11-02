"""Import build-time PEM pins into the runtime concatenated DER format."""
import base64
import pathlib
import re
import sys

source = pathlib.Path(sys.argv[1]).read_bytes() if sys.argv[1] else b""
if source.startswith(b"\x30"):
    result = source
else:
    pattern = rb"-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----"
    blocks = list(re.finditer(pattern, source))
    if source and (not 1 <= len(blocks) <= 8 or re.sub(pattern, b"", source).strip()):
        raise SystemExit("Expected a bounded PEM certificate bundle or DER")
    result = b"".join(base64.b64decode(re.sub(rb"\s", b"", m[1]), validate=True) for m in blocks)
pathlib.Path(sys.argv[2]).write_bytes(result)
