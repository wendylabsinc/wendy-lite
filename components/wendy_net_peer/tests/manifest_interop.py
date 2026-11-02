#!/usr/bin/env python3
"""Generate public native v4 P-256/ML-DSA-65 artifacts with reviewed WendyOS."""
import argparse
from pathlib import Path
import subprocess
import tempfile
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--go', required=True)
p.add_argument('--wendyos-root', type=Path, required=True)
p.add_argument('--driver', type=Path, required=True)
a = p.parse_args()
with tempfile.TemporaryDirectory(prefix='wendy-native-manifest-') as directory:
    subprocess.run([a.go, 'run', './cmd/wendy-net-manifest-comparison', '--fixtures-dir', directory],
                   cwd=a.wendyos_root.resolve(), check=True, stdout=subprocess.DEVNULL, timeout=60)
    subprocess.run([str(a.driver.resolve()), directory], check=True, timeout=30)
