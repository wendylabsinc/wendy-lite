#!/usr/bin/env python3
"""Normal finite-pool credit progress using functions from the patched SDK.

Copies the pinned NimBLE host into a temporary directory; never writes IDF_PATH.
The C harness supplies a finite ordinary MSYS pool and host lock/transport edges.
Whole-TU SDK compile checks remain separate from this portable behavior fixture.
"""
import argparse
import os
import re
from pathlib import Path
import shutil
import subprocess
import tempfile


def function(source, name):
    marker = '\n' + name + '('
    if marker in source:
        start = source.index(marker) + 1
        start = source.rfind('\n', 0, start - 1) + 1
    else:
        start = re.search(r'(?m)^static[^\n]*\b' + re.escape(name) + r'\(', source).start()
    opening = source.index('{', start)
    level = 1
    at = opening + 1
    while level:
        level += (source[at] == '{') - (source[at] == '}')
        at += 1
    return source[start:at] + '\n'


def copy_patched_host(project, idf, work):
    original = Path(idf) / 'components/bt/host/nimble/nimble/nimble/host'
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
    return host


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--idf', default=os.environ.get('IDF_PATH'))
    parser.add_argument('--sanitize', action='store_true')
    args = parser.parse_args()
    if not args.idf:
        parser.error('--idf or IDF_PATH is required')
    project = Path(__file__).resolve().parents[2]
    original = Path(args.idf) / 'components/bt/host/nimble/nimble/nimble/host'
    with tempfile.TemporaryDirectory(prefix='wendy-credit-retry-') as temporary:
        work = Path(temporary)
        host = copy_patched_host(project, args.idf, work)
        endpoint = (host / 'src/ble_l2cap_coc_priv.h').read_text()
        start = endpoint.index('struct ble_l2cap_coc_endpoint {')
        end = endpoint.index('};', start) + 2
        (work / 'nimble_credit_endpoint.inc').write_text(endpoint[start:end] + '\n')
        functions = []
        for source, names in [
            ('ble_l2cap_sig_cmd.c', ['ble_l2cap_sig_cmd_get']),
            ('ble_l2cap.c', ['ble_l2cap_tx']),
            ('ble_l2cap_sig.c', ['ble_l2cap_sig_le_credits_locked',
                                 'ble_l2cap_sig_le_credits']),
            ('ble_l2cap_coc.c', ['ble_l2cap_coc_credit_target',
                                 'ble_l2cap_coc_credit_flush',
                                 'ble_l2cap_coc_credit_request',
                                 'ble_l2cap_coc_credit_timer',
                                 'ble_l2cap_coc_recv_ready',
                                 'ble_l2cap_coc_rx_fn']),
            ('ble_l2cap_sig.c', ['ble_l2cap_sig_timer']),
        ]:
            text = (host / 'src' / source).read_text()
            for name in names:
                body = function(text, name)
                if name == 'ble_l2cap_coc_credit_target':
                    body = '#if BLE_L2CAP_SDU_BUFF_CNT > 1\n' + body + '#endif\n'
                functions.append(body)
        (work / 'nimble_credit_production.inc').write_text('\n'.join(functions))
        compiler = os.environ.get('CC', 'cc')
        command = [compiler, '-std=c11', '-g', '-Wall', '-Wextra', '-Werror',
                   '-I', str(work),
                   str(project / 'cmake/tests/nimble_credit_retry_test.c')]
        if args.sanitize:
            command += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
        for slots in [1, 2]:
            binary = work / f'credit-test-{slots}'
            subprocess.run(command + [f'-DTEST_RX_SLOTS={slots}',
                                      '-o', str(binary)], check=True, timeout=60)
            subprocess.run([str(binary)], check=True, timeout=30)
        # The live retry bits use existing storage, never a new per-channel member.
        assert 'uint8_t flags;' in endpoint[start:end]
        before = (original / 'src/ble_l2cap_coc_priv.h').read_text()
        before = before[before.index('struct ble_l2cap_coc_endpoint {'):].split('};', 1)[0]
        assert before == endpoint[start:end].split('};', 1)[0]
        print('Pinned SDK unchanged; CoC endpoint layout unchanged; normal finite-pool progress PASS')


if __name__ == '__main__':
    main()
