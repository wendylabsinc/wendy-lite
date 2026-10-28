#!/usr/bin/env python3
"""Positive current-Go signer → native operator lifecycle interop, no source edits."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', required=True)
    parser.add_argument('--wendyos-root', type=Path, required=True)
    parser.add_argument('--driver', type=Path, required=True)
    args = parser.parse_args()
    module = args.wendyos_root.resolve()
    source = Path(__file__).with_name('operator_lifecycle_wos_test.go.in')
    with tempfile.TemporaryDirectory(prefix='lite-operator-lifecycle-') as directory:
        overlay = Path(directory) / 'overlay.json'
        destination = module / 'internal/cli/netmesh/lite_operator_lifecycle_overlay_test.go'
        overlay.write_text(json.dumps({'Replace': {str(destination): str(source.resolve())}}))
        environment = dict(os.environ, WENDY_LITE_OPERATOR_LIFECYCLE=str(args.driver.resolve()),
                           GOTOOLCHAIN='go1.27.3', GOMAXPROCS='2')
        subprocess.run([args.go, 'test', '-p=1', '-count=1', '-timeout=60s',
                        '-overlay=' + str(overlay), '-run=^TestLiteOperatorLifecycleNormal$',
                        '-v', './internal/cli/netmesh'], cwd=module, env=environment, check=True)


if __name__ == '__main__':
    main()
