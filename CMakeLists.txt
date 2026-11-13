# WARNING (for developers and AI agents): native apps do NOT use this file.
#
# A native app is its own ESP-IDF project with its own top-level CMakeLists.txt
# (example: native_apps/blink-rgb). It gets the wendy-lite components through
# the component manager. Nothing set in this file reaches a native app.
#
# Before you add or change anything here (build properties, EXCLUDE_COMPONENTS,
# dependency patches, target checks, ...), do one of these:
#   - Make sure that no native app needs the change.
#   - Put the change where native apps also get it: a component's
#     CMakeLists.txt, project_include.cmake, Kconfig or idf_component.yml.
# If you cannot do either, stop and report the gap. Do not fix only the
# wendy-lite firmware build.

cmake_minimum_required(VERSION 3.29)

# WAMR component declares cmake_minimum_required(VERSION 3.5) which
# CMake 4.x rejects. Allow it via the compatibility policy.
set(CMAKE_POLICY_VERSION_MINIMUM 3.5)

set(EXTRA_COMPONENT_DIRS
    "${CMAKE_CURRENT_LIST_DIR}/components"
)

# The pinned WAMR release supports neither C61 nor S31. Exclude WASM adapters
# by target so this also applies when building without a board argfile.
if(IDF_TARGET STREQUAL "esp32c61" OR IDF_TARGET STREQUAL "esp32s31")
    set(EXCLUDE_COMPONENTS
        wendy_wasm wendy_hal wendy_hal_export wendy_app_usb wendy_ble_export
        wendy_callback wendy_safety wendy_storage wendy_net wendy_sys
        wendy_spi wendy_otel wendy_wasi_shim wendy_uart
    )
endif()

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
if(IDF_TARGET STREQUAL "esp32s31")
    include($ENV{IDF_PATH}/tools/cmake/version.cmake)
    if("${IDF_VERSION_MAJOR}.${IDF_VERSION_MINOR}" VERSION_LESS "6.1")
        message(FATAL_ERROR "ESP32-S31 requires ESP-IDF 6.1 or newer. Use idf.py --preview with ESP-IDF 6.1.")
    endif()
endif()
# Follow the enabled main-component dependencies. Optional WASM adapters must
# not pull their runtime into native firmware builds.
idf_build_set_property(MINIMAL_BUILD ON)
project(wendy_mcu)

# wendy_pki's project_include.cmake patches the bundled esp-pqc Mbed TLS.
include(cmake/dependency_patches.cmake)
wendy_patch_wamr()
wendy_patch_nimble()

# ESP32-P4 ships in several board layouts that differ in flash size and
# partition table, so a board overlay must be selected explicitly:
#     idf.py @boards/waveshare_lcd_4b.cfg          set-target esp32p4
#     idf.py @boards/dfr1172_firebeetle.cfg        set-target esp32p4
#     idf.py @boards/dfr1172_firebeetle_native.cfg set-target esp32p4
# Each boards/<board>.defaults sets CONFIG_WENDY_P4_BOARD_NAME.
if(IDF_TARGET STREQUAL "esp32p4")
    if(CONFIG_WENDY_P4_BOARD_NAME STREQUAL "")
        message(FATAL_ERROR
            "ESP32-P4 requires an explicit board overlay. Re-run set-target with one of:\n"
            "  idf.py @boards/waveshare_lcd_4b.cfg          set-target esp32p4\n"
            "  idf.py @boards/dfr1172_firebeetle.cfg        set-target esp32p4\n"
            "  idf.py @boards/dfr1172_firebeetle_native.cfg set-target esp32p4\n"
            "(see boards/ and the ESP32-P4 notes in README.md)")
    endif()
    message(STATUS "wendy-lite: ESP32-P4 board = ${CONFIG_WENDY_P4_BOARD_NAME}")
endif()
