cmake_minimum_required(VERSION 3.29)

# jo/wasmkit-runtime branch: WAMR replaced by WasmKit Embedded Swift.
# The WAMR managed component (espressif__wasm-micro-runtime) is no longer
# pulled in.  The CMAKE_POLICY_VERSION_MINIMUM workaround can be removed
# once the last WAMR reference is gone; keep it for now so other sub-CMakes
# that still declare 3.5 don't break.
set(CMAKE_POLICY_VERSION_MINIMUM 3.5)

set(EXTRA_COMPONENT_DIRS
    "${CMAKE_CURRENT_LIST_DIR}/components"
)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(wendy_mcu)

# ── RISC-V + Swift Embedded linker script patch ───────────────────────────────
# Swift Embedded on RISC-V generates an empty .got.plt section due to
# R_RISCV_CALL_PLT relocations.  ESP-IDF's /DISCARD/ block discards this section
# but doesn't explicitly place it first, triggering GNU ld 2.43's fatal
# "discarded output section: .got.plt" error.  We patch the generated sections.ld
# and its .in template at configure time to insert an explicit INFO section that
# gives .got.plt a home before /DISCARD/ runs.
if(IDF_TARGET MATCHES "^esp32c[0-9]$" OR IDF_TARGET STREQUAL "esp32c6")
    set(_LD_TEMPLATE "${CMAKE_BINARY_DIR}/esp-idf/esp_system/ld/sections.ld.in")
    set(_LD_OUT      "${CMAKE_BINARY_DIR}/esp-idf/esp_system/ld/sections.ld")

    foreach(_f "${_LD_TEMPLATE}" "${_LD_OUT}")
        if(EXISTS "${_f}")
            file(READ "${_f}" _ld_content)
            string(FIND "${_ld_content}" ".got.plt 0 (INFO)" _already)
            if(_already EQUAL -1)
                string(REPLACE
                    "  .riscv.attributes 0: { *(.riscv.attributes) }\n  /DISCARD/ :"
                    "  .riscv.attributes 0: { *(.riscv.attributes) }\n  .got.plt 0 (INFO) : { *(.got.plt) }\n  /DISCARD/ :"
                    _ld_content "${_ld_content}")
                file(WRITE "${_f}" "${_ld_content}")
                message(STATUS "wendy-lite: patched .got.plt placement in ${_f}")
            endif()
        endif()
    endforeach()
endif()

# ESP32-P4 ships in several board layouts that differ in flash size and
# partition table, so a board overlay must be selected explicitly:
#     idf.py @boards/waveshare_lcd_4b.cfg   set-target esp32p4
#     idf.py @boards/dfr1172_firebeetle.cfg set-target esp32p4
# Each boards/<board>.defaults sets CONFIG_WENDY_P4_BOARD_NAME.
if(IDF_TARGET STREQUAL "esp32p4")
    if(CONFIG_WENDY_P4_BOARD_NAME STREQUAL "")
        message(FATAL_ERROR
            "ESP32-P4 requires an explicit board overlay. Re-run set-target with one of:\n"
            "  idf.py @boards/waveshare_lcd_4b.cfg   set-target esp32p4\n"
            "  idf.py @boards/dfr1172_firebeetle.cfg set-target esp32p4\n"
            "(see boards/ and the ESP32-P4 notes in README.md)")
    endif()
    message(STATUS "wendy-lite: ESP32-P4 board = ${CONFIG_WENDY_P4_BOARD_NAME}")
endif()
