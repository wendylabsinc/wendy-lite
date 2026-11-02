#!/usr/bin/env python3
"""Check the SDK runner's staged CMake dependencies without a cross toolchain."""
from pathlib import Path
from contextlib import redirect_stdout
import io
import runpy
import subprocess
import sys
import tempfile
from unittest.mock import patch


runner = Path(__file__).with_name('sdk_component_test.py')
real_run = subprocess.run
with tempfile.TemporaryDirectory(prefix='wendy-sdk-fixture-') as temporary:
    temporary = Path(temporary).resolve()
    wamr = temporary / 'wamr'
    wamr.mkdir()
    work = temporary / 'project'

    def check_staged_project(command, *, cwd, check):
        assert command[0] == '/bin/bash' and cwd == work and check
        # This executes the same include as the generated SDK project. The
        # WAMR target is absent in script mode, so no IDF configuration is needed.
        real_run(['cmake', '-P', str(work / 'cmake/dependency_patches.cmake')], check=True)
        (work / 'sdkconfig').write_text(
            'CONFIG_WENDY_WASM=y\nCONFIG_WENDY_WASM_MAX_MEMORY_PAGES=0\n'
            'CONFIG_WAMR_ENABLE_AOT=y\nCONFIG_ESP_SYSTEM_ALLOW_RTC_FAST_MEM_AS_HEAP=y\n'
            '# CONFIG_WENDY_WASM_AOT_XIP is not set\n')
        memory = work / 'build/wendy_patched/wamr/core/iwasm/common/wasm_memory.c'
        memory.parent.mkdir(parents=True)
        memory.touch()

    arguments = [str(runner), '--idf', str(temporary / 'idf'), '--wamr', str(wamr),
                 '--work-dir', str(work), '--target', 'esp32c6', '--profile', 'default']
    with patch.object(sys, 'argv', arguments), patch.object(subprocess, 'run', check_staged_project), \
            redirect_stdout(io.StringIO()):
        runpy.run_path(str(runner), run_name='__main__')
print('SDK fixture CMake dependencies PASS (staging only; no SDK compile/link)')
