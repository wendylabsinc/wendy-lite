#!/usr/bin/env python3
"""Compile production module loads against a selected actual WAMR runtime."""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile
sys.dont_write_bytecode = True
from linear_replacement_test import function

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--wamr', type=Path, required=True)
parser.add_argument('--library', type=Path, required=True)
args = parser.parse_args()
here = Path(__file__).resolve().parent
source = (here.parent / 'src/wendy_wasm.c').read_text()
start = source.index('struct wendy_wasm_module {')
end = source.index('};', start) + 2
with tempfile.TemporaryDirectory(prefix='wendy-module-admission-') as directory:
    work = Path(directory)
    (work / 'module_admission_struct.inc').write_text(source[start:end])
    names = ['release_module_bytes', 'instantiate', 'wendy_wasm_load',
             'wendy_wasm_load_from_partition']
    (work / 'module_admission_production.inc').write_text('\n'.join(
        function(source, name) for name in names))
    command = [os.environ.get('CC', 'cc'), '-std=gnu11', '-g', '-Wall', '-Wextra', '-Werror',
               '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-I', str(work),
               '-I', str(here.parent / 'src'), '-I', str(args.wamr / 'core/iwasm/include'),
               str(here / 'module_admission_test.c'), str(here.parent / 'src/memory_limit.c'),
               str(args.library), '-lpthread', '-lm', '-o', str(work / 'test')]
    subprocess.run(command, check=True)
    subprocess.run([str(work / 'test')], check=True)
