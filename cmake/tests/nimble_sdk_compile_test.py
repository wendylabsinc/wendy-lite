#!/usr/bin/env python3
"""Compile copied, patched NimBLE host translation units with saved IDF flags.

Reads an existing firmware compile database and its generated headers. All
compiler output goes to a temporary directory; this is not a firmware build.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile


def digest(tree):
    return {str(path.relative_to(tree)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in tree.rglob('*') if path.is_file()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--idf', default=os.environ.get('IDF_PATH'))
    parser.add_argument('--compile-commands', type=Path, required=True)
    args = parser.parse_args()
    if not args.idf:
        parser.error('--idf or IDF_PATH is required')
    project = Path(__file__).resolve().parents[2]
    original = Path(args.idf).resolve() / 'components/bt/host/nimble/nimble/nimble/host'
    units = [entry for entry in json.loads(args.compile_commands.read_text())
             if str(original / 'src') + '/' in entry['file'] or
             '/wendy_patched/nimble_host/src/' in entry['file']]
    if not units:
        parser.error('compile database has no NimBLE host/src translation units')
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location('credit_fixture',
        Path(__file__).with_name('nimble_credit_retry_test.py'))
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    before = digest(original)
    with tempfile.TemporaryDirectory(prefix='wendy-sdk-compile-') as temporary:
        work = Path(temporary)
        host = helper.copy_patched_host(project, args.idf, work)
        for entry in units:
            old_host = str(Path(entry['file']).parent.parent)
            command = entry.get('arguments') or shlex.split(entry['command'])
            command = [arg.replace(old_host + '/', str(host) + '/')
                       .replace(str(original) + '/', str(host) + '/') for arg in command]
            command[command.index('-o') + 1] = str(work / (Path(entry['file']).name + '.o'))
            # IDF normally uses absolute paths. Resolve relative search paths
            # and response files while keeping the compiler cwd private too.
            directory = Path(entry['directory'])
            for index, arg in enumerate(command):
                if arg.startswith('-I') and len(arg) > 2 and not Path(arg[2:]).is_absolute():
                    command[index] = '-I' + str(directory / arg[2:])
                elif arg.startswith('@') and not Path(arg[1:]).is_absolute():
                    command[index] = '@' + str(directory / arg[1:])
                elif arg == '-MF':
                    command[index + 1] = str(work / (Path(entry['file']).name + '.d'))
            subprocess.run(command, cwd=work, check=True, timeout=60)
        assert digest(original) == before, 'Installed SDK host changed'
        print(f'{len(units)} whole SDK host units compiled; {len(before)} installed host files unchanged')


if __name__ == '__main__':
    main()
