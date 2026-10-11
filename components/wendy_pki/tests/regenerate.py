#!/usr/bin/env python3
"""Regenerate disposable fixtures with a local pki-core checkout."""
import pathlib
import shutil
import subprocess
import sys
import tempfile

here = pathlib.Path(__file__).resolve().parent
pki = pathlib.Path(sys.argv[1]).resolve()
verifier = pathlib.Path(sys.argv[2]).resolve()
fixtures = here / "fixtures"
fixtures.mkdir(exist_ok=True)
subprocess.run([verifier, "--request", fixtures / "request.der"], check=True)
with tempfile.TemporaryDirectory(prefix="litefixtures_", dir=pki) as temporary:
    target = pathlib.Path(temporary)
    shutil.copy(here / "pkicore_fixtures.go", target / "main.go")
    subprocess.run(["go", "run", "./" + target.name, str(fixtures)], cwd=pki, check=True)
subprocess.run([verifier, fixtures], check=True)
