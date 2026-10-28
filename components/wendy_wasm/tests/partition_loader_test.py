#!/usr/bin/env python3
"""Run production partition loader ownership paths with SDK edges stubbed."""
import os
import sys
sys.dont_write_bytecode = True
from pathlib import Path
import subprocess
import tempfile
from linear_replacement_test import function

root = Path(__file__).resolve().parents[3]
source = (root / 'components/wendy_wasm/src/wendy_wasm.c').read_text()
with tempfile.TemporaryDirectory(prefix='wendy-partition-loader-') as temporary:
    work = Path(temporary)
    (work / 'partition_loader_production.inc').write_text('\n'.join(
        function(source, name) for name in ['release_module_bytes', 'wendy_wasm_load_from_partition']))
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-g', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-I', str(work),
                    str(Path(__file__).with_suffix('.c')), '-o', str(work / 'test')], check=True)
    subprocess.run([str(work / 'test')], check=True)
