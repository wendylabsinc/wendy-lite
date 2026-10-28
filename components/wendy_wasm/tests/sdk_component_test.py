#!/usr/bin/env python3
"""Compile/link the production wrapper and patched WAMR in a private IDF project.

No firmware is flashed and no SDK/dependency source is modified. Pass a pristine
pinned WAMR source and an empty output directory. Profiles cover SRAM defaults,
PSRAM metadata/replacement, and the optional RTC + AOT XIP placement experiment.
"""
import argparse
from pathlib import Path
import shlex
import shutil
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--idf', type=Path, required=True)
parser.add_argument('--wamr', type=Path, required=True)
parser.add_argument('--work-dir', type=Path, required=True)
parser.add_argument('--target', choices=['esp32c6', 'esp32c5'], required=True)
parser.add_argument('--profile', choices=['default', 'psram', 'rtc-xip'], required=True)
args = parser.parse_args()
root = Path(__file__).resolve().parents[3]
work = args.work_dir.resolve()
work.mkdir(parents=True, exist_ok=True)
if any(work.iterdir()):
    parser.error('--work-dir must be empty')
if args.profile == 'psram' and args.target != 'esp32c5':
    parser.error('PSRAM profile requires esp32c5')
shutil.copytree(args.wamr, work / 'components/espressif__wasm-micro-runtime')
shutil.copytree(root / 'components/wendy_wasm', work / 'components/wendy_wasm')
shutil.copytree(root / 'patches', work / 'patches')
(work / 'cmake').mkdir()
shutil.copyfile(root / 'cmake/dependency_patches.cmake', work / 'cmake/dependency_patches.cmake')
(work / 'main').mkdir()
(work / 'CMakeLists.txt').write_text('''cmake_minimum_required(VERSION 3.16)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(wasm_component_review)
include(cmake/dependency_patches.cmake)
wendy_patch_wamr()
''')
(work / 'main/CMakeLists.txt').write_text('idf_component_register(SRCS "main.c" REQUIRES wendy_wasm)\n')
(work / 'main/Kconfig.projbuild').write_text('config WENDY_CORE_WASM_APP_SUPPORT\n    bool\n    default y\n')
(work / 'main/main.c').write_text('''#include "wendy_wasm.h"
void app_main(void) {
    wendy_wasm_config_t cfg = WENDY_WASM_CONFIG_DEFAULT();
    wendy_wasm_init(&cfg);
    wendy_wasm_module_handle_t module = NULL;
    wendy_wasm_load_from_partition("wasm_a", &module);
    wendy_wasm_replacement_finish(wendy_wasm_replacement_begin(module));
    wendy_wasm_unload(module);
}
''')
config = 'CONFIG_WENDY_WASM=y\nCONFIG_WAMR_ENABLE_INTERP=y\n'
if args.profile == 'psram':
    config += 'CONFIG_SPIRAM=y\nCONFIG_SPIRAM_MODE_QUAD=y\nCONFIG_WENDY_WASM_USE_PSRAM=y\nCONFIG_WENDY_WASM_MAX_MEMORY_PAGES=80\n'
if args.profile == 'rtc-xip':
    config += 'CONFIG_WAMR_ENABLE_AOT=y\nCONFIG_WENDY_WASM_AOT_XIP=y\nCONFIG_WENDY_WASM_PREFER_RTC_RAM=y\nCONFIG_WENDY_WASM_MAX_MEMORY_PAGES=80\n'
(work / 'sdkconfig.defaults').write_text(config)
command = 'source ' + shlex.quote(str(args.idf.resolve() / 'export.sh'))
command += ' && idf.py set-target ' + args.target + ' && idf.py build'
subprocess.run(['/bin/bash', '-c', command], cwd=work, check=True)
# Verify that a silently unavailable Kconfig option did not weaken coverage.
sdkconfig = (work / 'sdkconfig').read_text()
assert 'CONFIG_WENDY_WASM=y' in sdkconfig
if args.profile == 'default':
    assert 'CONFIG_WENDY_WASM_MAX_MEMORY_PAGES=0' in sdkconfig
    assert '# CONFIG_WENDY_WASM_AOT_XIP is not set' in sdkconfig or 'CONFIG_WAMR_ENABLE_AOT=y' not in sdkconfig
    assert '# CONFIG_WENDY_WASM_PREFER_RTC_RAM is not set' in sdkconfig or 'CONFIG_ESP_SYSTEM_ALLOW_RTC_FAST_MEM_AS_HEAP=y' not in sdkconfig
if args.profile == 'psram':
    assert 'CONFIG_SPIRAM=y' in sdkconfig and 'CONFIG_WENDY_WASM_USE_PSRAM=y' in sdkconfig
if args.profile == 'rtc-xip':
    assert 'CONFIG_WENDY_WASM_AOT_XIP=y' in sdkconfig and 'CONFIG_WENDY_WASM_PREFER_RTC_RAM=y' in sdkconfig
assert (work / 'build/wendy_patched/wamr/core/iwasm/common/wasm_memory.c').is_file()
print('SDK component compile/link PASS:', args.target, args.profile)
