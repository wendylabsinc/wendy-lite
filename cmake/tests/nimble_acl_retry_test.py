#!/usr/bin/env python3
"""Valid queued ACL traffic under finite allocator/controller pressure.

Execute actual patched SDK queue, HCI fragmentation and retry-timer functions.
Copy only into a private temporary host tree; never modify the installed SDK.
"""
import argparse
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--idf', default=os.environ.get('IDF_PATH'))
    parser.add_argument('--host', help='Read an already patched private host tree')
    parser.add_argument('--sanitize', action='store_true')
    args = parser.parse_args()
    if not args.host and not args.idf:
        parser.error('--idf, --host or IDF_PATH is required')
    project = Path(__file__).resolve().parents[2]
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location('credit_fixture',
        Path(__file__).with_name('nimble_credit_retry_test.py'))
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    with tempfile.TemporaryDirectory(prefix='wendy-acl-retry-') as temporary:
        work = Path(temporary)
        if args.host:
            host = Path(args.host).resolve()
        else:
            original = Path(args.idf) / 'components/bt/host/nimble/nimble/nimble/host'
            host = work / 'host'
            shutil.copytree(original, host)
            env = os.environ.copy()
            env.pop('GIT_DIR', None)
            env.pop('GIT_WORK_TREE', None)
            env['GIT_CEILING_DIRECTORIES'] = str(work)
            for patch in ('idf-nimble-coc-crossed-disconnect.patch',
                          'idf-nimble-coc-credit-retry.patch',
                          'idf-nimble-coc-backed-credit-window.patch',
                          'idf-nimble-acl-queued-retry.patch'):
                subprocess.run(['git', 'apply', '--no-index', str(project / 'patches' / patch)],
                    cwd=host, env=env, check=True, timeout=30)
        production = []
        for source, names in (
            ('ble_hs_hci.c', ('ble_hs_hci_acl_tx_now', 'ble_hs_hci_acl_tx')),
            ('ble_l2cap.c', ('ble_l2cap_tx',)),
            ('ble_hs.c', ('ble_hs_wakeup_tx_conn', 'ble_hs_wakeup_tx',
                         'ble_hs_sched_tx_retry', 'ble_hs_tx_retry_timer'))):
            text = (host / 'src' / source).read_text()
            production.extend(helper.function(text, name) for name in names)
        (work / 'production.inc').write_text('\n'.join(production))
        for maximum in (251, 8):
            binary = work / ('acl-' + str(maximum))
            command = [os.environ.get('CC', 'cc'), '-std=c11', '-g', '-Wall', '-Wextra',
                '-Werror', '-Wno-unused-function', '-Wno-misleading-indentation',
                '-I', str(work), '-DHAVE_RETRY_TIMER=1', '-DTEST_ACL_MAX=' + str(maximum),
                str(Path(__file__).with_suffix('.c')), '-o', str(binary)]
            if args.sanitize:
                command += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
            subprocess.run(command, check=True, timeout=60)
            subprocess.run([str(binary)], check=True, timeout=30)
        print('Normal SDK queued ACL bytes/PB/ownership and finite-pressure retry PASS')


if __name__ == '__main__':
    main()
