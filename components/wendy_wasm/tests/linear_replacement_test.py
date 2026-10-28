#!/usr/bin/env python3
"""Positive hot-replacement lifetime using pinned WAMR paths and IDF TLSF.
Copies dependency sources privately; never modifies IDF or generated builds.
"""
import argparse
import re
import os
from pathlib import Path
import subprocess
import tempfile


def function(source, name):
    for match in re.finditer(r'(?m)^(?:[A-Za-z_]\w*[ \t*]+)*' + name + r'\(', source):
        opening = source.index('{', match.start())
        if ';' in source[match.start():opening]:
            continue
        start = match.start()
        if source[start:source.index('(', start)].strip() == name:
            start = source.rfind('\n', 0, start - 1) + 1
        level, at = 1, opening + 1
        while level:
            level += (source[at] == '{') - (source[at] == '}')
            at += 1
        return source[start:at] + '\n'
    raise ValueError('missing function ' + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--idf', required=True)
    parser.add_argument('--sanitize', action='store_true')
    parser.add_argument('--wamr', type=Path, help='pristine pinned WAMR source tree')
    args = parser.parse_args()
    project = Path(__file__).resolve().parents[3]
    original = args.wamr or project / 'managed_components/espressif__wasm-micro-runtime'
    memory = (original / 'core/iwasm/common/wasm_memory.c').read_text()
    with tempfile.TemporaryDirectory(prefix='wendy-linear-replacement-') as temp:
        work = Path(temp)
        target = work / 'core/iwasm/common/wasm_memory.c'
        target.parent.mkdir(parents=True)
        target.write_text(memory)
        env = os.environ.copy()
        env.pop('GIT_DIR', None)
        env.pop('GIT_WORK_TREE', None)
        env['GIT_CEILING_DIRECTORIES'] = str(work.parent)
        for name in ['espidf_memmap.c', 'platform_internal.h']:
            dest = work / 'core/shared/platform/esp-idf' / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text((original / 'core/shared/platform/esp-idf' / name).read_text())
        for patch in ['wamr-idf6-platform.patch', 'wamr-linear-mapping-replacement.patch']:
            subprocess.run(['git', 'apply', '--no-index', str(project / 'patches' / patch)],
                           cwd=work, env=env, check=True)
        memory = target.read_text()
        sources = [
            ('core/shared/platform/esp-idf/espidf_memmap.c', ['os_mmap', 'os_munmap']),
            ('core/shared/platform/esp-idf/espidf_malloc.c', ['os_free']),
        ]
        body = []
        for source, names in sources:
            text = ((work if (work / source).exists() else original) / source).read_text()
            body += [function(text, name) for name in names]
        body += [function(memory, name) for name in [
            'wasm_munmap_linear_memory', 'wasm_mremap_linear_memory',
            'wasm_mmap_linear_memory', 'wasm_allocate_linear_memory',
            'wasm_deallocate_linear_memory']]
        weak_start = memory.index('#if defined(BH_PLATFORM_ESP_IDF) && WASM_MEM_ALLOC_WITH_USAGE == 0')
        weak_end = memory.index('#endif', weak_start) + len('#endif')
        (work / 'linear_production.inc').write_text(memory[weak_start:weak_end] + '\n' + '\n'.join(body))
        core = (project / 'components/wendy_core/src/wendy_core.c').read_text()
        wrapper = (project / 'components/wendy_wasm/src/wendy_wasm.c').read_text()
        lifecycle = [function(wrapper, name) for name in [
            'wendy_wasm_replacement_begin', 'wendy_wasm_replacement_finish']]
        lifecycle += [function(core, name) for name in [
            'mark_current_module_unloaded', 'wasm_app_stop_on_control_thread',
            'wasm_app_stop_for_flash_on_control_thread', 'wasm_app_start_on_control_thread']]
        (work / 'linear_core_production.inc').write_text('\n'.join(lifecycle))
        command = [os.environ.get('CC', 'cc'), '-std=gnu11', '-g', '-Wall', '-Wextra', '-Werror',
                   '-Wno-unused-parameter', '-I', str(work), '-I', str(Path(args.idf) / 'components/heap/tlsf'),
                   '-I', str(Path(args.idf) / 'components/heap/tlsf/include'),
                   '-I', str(project / 'components/wendy_wasm/src'),
                   str(project / 'components/wendy_wasm/tests/linear_replacement_test.c'),
                   str(project / 'components/wendy_wasm/src/linear_replacement.c'),
                   str(Path(args.idf) / 'components/heap/tlsf/tlsf.c'), '-o', str(work / 'test')]
        if args.sanitize:
            command += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
        subprocess.run(command, check=True)
        subprocess.run([str(work / 'test')], check=True)


if __name__ == '__main__':
    main()
