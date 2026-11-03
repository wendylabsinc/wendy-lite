"""Compile the exact topology mailbox with optional local observation profiles."""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parent.parent
common = root.parent / 'wendy_net_common'
nanopb = root.parent / 'nanopb'
with tempfile.TemporaryDirectory() as temporary:
    work = Path(temporary)
    subprocess.run(['python3', str(root / 'tests/extract_topology_fixture.py'),
                    str(root / 'src/peer.c'), str(work / 'topology_driver.inc')], check=True)
    for observe, constrained in ((0, 0), (1, 0), (1, 1)):
        executable = work / f'carrier-observation-{observe}-{constrained}'
        subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-Wno-misleading-indentation', '-fsanitize=address,undefined', '-pthread',
                        '-DWENDY_NET_MEMORY_HOST_BUDGET_TEST=1',
                        '-DCONFIG_WENDY_NET_CARRIER_OBSERVATION=' + str(observe),
                        '-DCONFIG_WENDY_NET_CONSTRAINED_PROFILE=' + str(constrained),
                        '-I' + str(work), '-I' + str(root / 'src'),
                        '-I' + str(root.parent / 'wendy_com/include'),
                        '-I' + str(nanopb), '-I' + str(common / 'include'),
                        str(root / 'tests/topology_driver_success_test.c'),
                        str(root / 'src/topology_record.c'), str(common / 'src/memory.c'),
                        str(common / 'src/runtime_memory.c'), str(nanopb / 'pb_common.c'),
                        str(nanopb / 'pb_encode.c'), '-o', str(executable)], check=True)
        subprocess.run([str(executable)], check=True, timeout=20)
        print(f'local carrier mailbox observe={observe} constrained={constrained}: PASS', flush=True)
