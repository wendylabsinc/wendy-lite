#!/usr/bin/env python3
"""Ordinary simultaneous CoC close through the patched SDK signaling functions."""
import argparse
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--idf', default=os.environ.get('IDF_PATH'))
    parser.add_argument('--sanitize', action='store_true')
    args = parser.parse_args()
    if not args.idf:
        parser.error('--idf or IDF_PATH is required')
    project = Path(__file__).resolve().parents[2]
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location('credit_fixture',
        Path(__file__).with_name('nimble_credit_retry_test.py'))
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    with tempfile.TemporaryDirectory(prefix='wendy-disconnect-') as temporary:
        work = Path(temporary)
        host = helper.copy_patched_host(project, args.idf, work)
        source = (host / 'src/ble_l2cap_sig.c').read_text()
        names = ('ble_l2cap_sig_extract_chan_disconnect', 'ble_l2cap_sig_disc_req_rx',
                 'ble_l2cap_sig_coc_disconnect_cb', 'ble_l2cap_sig_disc_rsp_rx')
        (work / 'production.inc').write_text('\n'.join(helper.function(source, name) for name in names))
        binary = work / 'disconnect'
        command = [os.environ.get('CC', 'cc'), '-std=c11', '-g', '-Wall', '-Wextra',
                   '-Werror', '-Wno-unused-parameter', '-I', str(work),
                   str(Path(__file__).with_suffix('.c')), '-o', str(binary)]
        if args.sanitize:
            command += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
        subprocess.run(command, check=True, timeout=60)
        subprocess.run([str(binary)], check=True, timeout=30)


if __name__ == '__main__':
    main()
