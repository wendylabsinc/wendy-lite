# wendy_wasmkit — WasmKit-backed WASM runtime for wendy-lite
#
# This component replaces wendy_wasm (WAMR-based) with the WasmKit Embedded
# Swift runtime.  It exposes the same wendy_wasm.h C API so nothing else in
# the firmware needs to change.
#
# Requirements:
#   - A Swift toolchain that supports `riscv32-none-none-eabi` Embedded Swift.
#     The toolchain binary is found via the SWIFT_TOOLCHAIN_BIN env var (falls
#     back to PATH).  Set e.g.:
#       export SWIFT_TOOLCHAIN_BIN=/path/to/swift-6.x-RELEASE/usr/bin
#   - WasmKit source tree at ${WASMKIT_ROOT} (default: sibling of this repo at
#     ../../../../swiftwasm/WasmKit relative to this file, i.e.
#     ~/git/swiftwasm/WasmKit when wendy-lite lives at ~/git/wendy/wendy-lite).
#     Override with -DWASMKIT_ROOT=/custom/path.

cmake_minimum_required(VERSION 3.16)

# ── Locate WasmKit ───────────────────────────────────────────────────────────

if(NOT DEFINED WASMKIT_ROOT)
    get_filename_component(WASMKIT_ROOT
        "${CMAKE_CURRENT_LIST_DIR}/../../../../swiftwasm/WasmKit"
        ABSOLUTE)
endif()

if(NOT EXISTS "${WASMKIT_ROOT}/Sources/WasmKit/Engine.swift")
    message(FATAL_ERROR
        "WasmKit not found at '${WASMKIT_ROOT}'. "
        "Clone https://github.com/swiftwasm/WasmKit (branch jo/embedded-runtime-v2) "
        "there, or set -DWASMKIT_ROOT=/path/to/WasmKit.")
endif()

# ── Locate Swift compiler ─────────────────────────────────────────────────────

if(DEFINED ENV{SWIFT_TOOLCHAIN_BIN})
    set(SWIFTC "$ENV{SWIFT_TOOLCHAIN_BIN}/swiftc")
else()
    find_program(SWIFTC swiftc REQUIRED)
endif()

message(STATUS "wendy_wasmkit: using Swift compiler at '${SWIFTC}'")
message(STATUS "wendy_wasmkit: using WasmKit at '${WASMKIT_ROOT}'")

# ── ESP-IDF component registration (C bridge + include export) ────────────────

idf_component_register(
    SRCS ""
    LDFRAGMENTS "linker.lf"
    INCLUDE_DIRS "include"
    PRIV_REQUIRES
        freertos
        esp_common
        esp_hw_support
        esp_partition
        heap
        spi_flash
        log
        nvs_flash
        wendy_hal
        wendy_callback
        wendy_sys
        wendy_storage
        wendy_uart
        wendy_spi
        wendy_otel
        wendy_ble
        wendy_net
        wendy_app_usb
)

# ── Collect Swift source files ────────────────────────────────────────────────

# WasmTypes
set(WASMTYPES_SOURCES
    "${WASMKIT_ROOT}/Sources/WasmTypes/WasmTypes.swift"
    "${WASMKIT_ROOT}/Sources/WasmTypes/GuestMemory.swift"
)

# WasmParserCore (explicit list — avoids duplicate WasmTypes.swift name clash)
set(WASMPARSER_CORE_SOURCES
    "${WASMKIT_ROOT}/Sources/WasmParserCore/BinaryInstructionDecoder.swift"
    "${WASMKIT_ROOT}/Sources/WasmParserCore/ComponentParser.swift"
    "${WASMKIT_ROOT}/Sources/WasmParserCore/InstructionVisitor.swift"
    "${WASMKIT_ROOT}/Sources/WasmParserCore/LEB.swift"
    "${WASMKIT_ROOT}/Sources/WasmParserCore/ParsingLimits.swift"
    "${WASMKIT_ROOT}/Sources/WasmParserCore/Stream/ByteStream.swift"
    "${WASMKIT_ROOT}/Sources/WasmParserCore/WasmParserCore.swift"
    "${WASMKIT_ROOT}/Sources/WasmParserCore/WasmParserError.swift"
    "${WASMKIT_ROOT}/Sources/WasmParserCore/WasmTypes.swift"
)

# WasmKit engine (subset that compiles with Embedded – no file I/O,
# no ComponentModel, no SIMD extension instructions for now)
set(WASMKIT_ENGINE_SOURCES
    "${WASMKIT_ROOT}/Sources/WasmKit/Engine.swift"
    "${WASMKIT_ROOT}/Sources/WasmKit/Imports.swift"
    "${WASMKIT_ROOT}/Sources/WasmKit/Module.swift"
    "${WASMKIT_ROOT}/Sources/WasmKit/ModuleParser.swift"
    "${WASMKIT_ROOT}/Sources/WasmKit/ResourceLimiter.swift"
    "${WASMKIT_ROOT}/Sources/WasmKit/SIMDOpcode.swift"
    "${WASMKIT_ROOT}/Sources/WasmKit/Translator.swift"
    "${WASMKIT_ROOT}/Sources/WasmKit/Validator.swift"
    "${WASMKIT_ROOT}/Sources/WasmKit/WasmKitError.swift"
    "${WASMKIT_ROOT}/Sources/WasmKit/Execution/AtomicParkingLot.swift"
    "${WASMKIT_ROOT}/Sources/WasmKit/Execution/DispatchInstruction.swift"
    "${WASMKIT_ROOT}/Sources/WasmKit/Execution/Errors.swift"
    "${WASMKIT_ROOT}/Sources/WasmKit/Execution/Execution.swift"
    "${WASMKIT_ROOT}/Sources/WasmKit/Execution/Function.swift"
    "${WASMKIT_ROOT}/Sources/WasmKit/Execution/Instances.swift"
    "${WASMKIT_ROOT}/Sources/WasmKit/Execution/DebuggerInstructionMapping.swift"
    "${WASMKIT_ROOT}/Sources/WasmKit/Execution/ConstEvaluation.swift"
    "${WASMKIT_ROOT}/Sources/WasmKit/Execution/IO.swift"
    "${WASMKIT_ROOT}/Sources/WasmKit/Execution/NameRegistry.swift"
    # Profiler.swift excluded — imports SystemExtras/SystemPackage (not available in Embedded)
    "${WASMKIT_ROOT}/Sources/WasmKit/Execution/Runtime.swift"
    "${WASMKIT_ROOT}/Sources/WasmKit/Execution/Store.swift"
    "${WASMKIT_ROOT}/Sources/WasmKit/Execution/StoreAllocator.swift"
    "${WASMKIT_ROOT}/Sources/WasmKit/Execution/UntypedValue.swift"
    "${WASMKIT_ROOT}/Sources/WasmKit/Execution/Value.swift"
    "${WASMKIT_ROOT}/Sources/WasmKit/Execution/V128Storage.swift"
    "${WASMKIT_ROOT}/Sources/WasmKit/Execution/Instructions/Control.swift"
    "${WASMKIT_ROOT}/Sources/WasmKit/Execution/Instructions/Instruction.swift"
    "${WASMKIT_ROOT}/Sources/WasmKit/Execution/Instructions/InstructionSupport.swift"
    "${WASMKIT_ROOT}/Sources/WasmKit/Execution/Instructions/Memory.swift"
    "${WASMKIT_ROOT}/Sources/WasmKit/Execution/Instructions/Misc.swift"
    "${WASMKIT_ROOT}/Sources/WasmKit/Execution/Instructions/Table.swift"
    "${WASMKIT_ROOT}/Sources/WasmKit/Execution/Instructions/SIMDCore.swift"
    "${WASMKIT_ROOT}/Sources/WasmKit/Execution/Instructions/SIMDMemoryAndLane.swift"
    "${WASMKIT_ROOT}/Sources/WasmKit/Execution/Instructions/SIMDNumeric.swift"
    "${WASMKIT_ROOT}/Sources/WasmKit/Execution/Instructions/V128Lanes.swift"
)

# Bridge + runtime Swift sources specific to wendy-lite
set(WENDY_SWIFT_SOURCES
    "${CMAKE_CURRENT_LIST_DIR}/src/WendyRuntime.swift"
    "${CMAKE_CURRENT_LIST_DIR}/src/WendyImports.swift"
)

set(ALL_SWIFT_SOURCES
    ${WASMTYPES_SOURCES}
    ${WASMPARSER_CORE_SOURCES}
    ${WASMKIT_ENGINE_SOURCES}
    ${WENDY_SWIFT_SOURCES}
)

# ── Collect include directories from registered component dependencies ─────────

# Get the IDF path
idf_build_get_property(IDF_PATH IDF_PATH)
idf_build_get_property(IDF_TARGET IDF_TARGET)

# Build the -Xcc -I list from the component's private dependencies.
# We resolve the include directories after all components are registered.
# Because CMake generator expressions can't be used in COMMAND strings directly,
# we write a CMake script that is invoked at build time to capture the final list.

set(SWIFT_OBJ_DIR "${CMAKE_CURRENT_BINARY_DIR}/swift_objs")
set(SWIFT_STATIC_LIB "${SWIFT_OBJ_DIR}/libwendy_wasmkit_swift.a")

# Complete include path list extracted from compile_commands.json (wendy_hal_export
# component on esp32c6 target).  This matches exactly what ESP-IDF passes to GCC.
# WasmKit's _CWasmKit include prepended; toolchain stdlib headers appended last.
set(SWIFT_IDF_INCLUDES
    # WasmKit internal C shim
    "${WASMKIT_ROOT}/Sources/_CWasmKit/include"
    # Our own component include (stub wasm_export.h, wendy_wasm.h)
    "${CMAKE_CURRENT_LIST_DIR}/include"
    # Generated sdkconfig (must be early so FreeRTOSConfig.h etc. are found)
    "${CMAKE_BINARY_DIR}/config"
    # ── Extracted from compile_commands.json ───────────────────────────────────
    "${IDF_PATH}/components/newlib/platform_include"
    "${IDF_PATH}/components/freertos/config/include"
    "${IDF_PATH}/components/freertos/config/include/freertos"
    "${IDF_PATH}/components/freertos/config/riscv/include"
    "${IDF_PATH}/components/freertos/FreeRTOS-Kernel/include"
    "${IDF_PATH}/components/freertos/FreeRTOS-Kernel/portable/riscv/include"
    "${IDF_PATH}/components/freertos/FreeRTOS-Kernel/portable/riscv/include/freertos"
    "${IDF_PATH}/components/freertos/esp_additions/include"
    "${IDF_PATH}/components/esp_hw_support/include"
    "${IDF_PATH}/components/esp_hw_support/include/soc"
    "${IDF_PATH}/components/esp_hw_support/include/soc/esp32c6"
    "${IDF_PATH}/components/esp_hw_support/dma/include"
    "${IDF_PATH}/components/esp_hw_support/ldo/include"
    "${IDF_PATH}/components/esp_hw_support/debug_probe/include"
    "${IDF_PATH}/components/esp_hw_support/mspi_timing_tuning/include"
    "${IDF_PATH}/components/esp_hw_support/mspi_timing_tuning/tuning_scheme_impl/include"
    "${IDF_PATH}/components/esp_hw_support/power_supply/include"
    "${IDF_PATH}/components/esp_hw_support/port/esp32c6"
    "${IDF_PATH}/components/esp_hw_support/port/esp32c6/include"
    "${IDF_PATH}/components/esp_hw_support/port/esp32c6/private_include"
    "${IDF_PATH}/components/heap/include"
    "${IDF_PATH}/components/heap/tlsf"
    "${IDF_PATH}/components/log/include"
    "${IDF_PATH}/components/soc/include"
    "${IDF_PATH}/components/soc/esp32c6"
    "${IDF_PATH}/components/soc/esp32c6/include"
    "${IDF_PATH}/components/soc/esp32c6/register"
    "${IDF_PATH}/components/hal/platform_port/include"
    "${IDF_PATH}/components/hal/esp32c6/include"
    "${IDF_PATH}/components/hal/include"
    "${IDF_PATH}/components/esp_rom/include"
    "${IDF_PATH}/components/esp_rom/esp32c6/include"
    "${IDF_PATH}/components/esp_rom/esp32c6/include/esp32c6"
    "${IDF_PATH}/components/esp_rom/esp32c6"
    "${IDF_PATH}/components/esp_common/include"
    "${IDF_PATH}/components/esp_system/include"
    "${IDF_PATH}/components/esp_system/port/soc"
    "${IDF_PATH}/components/esp_system/port/include/riscv"
    "${IDF_PATH}/components/esp_system/port/include/private"
    "${IDF_PATH}/components/riscv/include"
    "${IDF_PATH}/components/lwip/include"
    "${IDF_PATH}/components/lwip/include/apps"
    "${IDF_PATH}/components/lwip/include/apps/sntp"
    "${IDF_PATH}/components/lwip/lwip/src/include"
    "${IDF_PATH}/components/lwip/port/include"
    "${IDF_PATH}/components/lwip/port/freertos/include"
    "${IDF_PATH}/components/lwip/port/esp32xx/include"
    "${IDF_PATH}/components/lwip/port/esp32xx/include/arch"
    "${IDF_PATH}/components/lwip/port/esp32xx/include/sys"
    "${IDF_PATH}/components/driver/deprecated"
    "${IDF_PATH}/components/driver/i2c/include"
    "${IDF_PATH}/components/driver/touch_sensor/include"
    "${IDF_PATH}/components/driver/twai/include"
    "${IDF_PATH}/components/esp_pm/include"
    "${IDF_PATH}/components/esp_ringbuf/include"
    "${IDF_PATH}/components/esp_driver_gpio/include"
    "${IDF_PATH}/components/esp_driver_pcnt/include"
    "${IDF_PATH}/components/esp_driver_gptimer/include"
    "${IDF_PATH}/components/esp_driver_spi/include"
    "${IDF_PATH}/components/esp_driver_mcpwm/include"
    "${IDF_PATH}/components/esp_driver_ana_cmpr/include"
    "${IDF_PATH}/components/esp_driver_i2s/include"
    "${IDF_PATH}/components/esp_driver_sdmmc/include"
    "${IDF_PATH}/components/sdmmc/include"
    "${IDF_PATH}/components/esp_driver_sdspi/include"
    "${IDF_PATH}/components/esp_driver_sdio/include"
    "${IDF_PATH}/components/esp_driver_dac/include"
    "${IDF_PATH}/components/esp_driver_rmt/include"
    "${IDF_PATH}/components/esp_driver_tsens/include"
    "${IDF_PATH}/components/esp_driver_sdm/include"
    "${IDF_PATH}/components/esp_driver_i2c/include"
    "${IDF_PATH}/components/esp_driver_uart/include"
    "${IDF_PATH}/components/vfs/include"
    "${IDF_PATH}/components/esp_driver_ledc/include"
    "${IDF_PATH}/components/esp_driver_parlio/include"
    "${IDF_PATH}/components/esp_driver_usb_serial_jtag/include"
    "${IDF_PATH}/components/esp_driver_twai/include"
    "${IDF_PATH}/components/esp_timer/include"
    "${IDF_PATH}/components/esp_adc/include"
    "${IDF_PATH}/components/esp_adc/interface"
    "${IDF_PATH}/components/esp_adc/esp32c6/include"
    "${IDF_PATH}/components/esp_adc/deprecated/include"
    "${IDF_PATH}/components/nvs_flash/include"
    "${IDF_PATH}/components/esp_partition/include"
    "${IDF_PATH}/components/esp_timer/include"
    "${IDF_PATH}/components/esp_event/include"
    "${IDF_PATH}/components/esp_phy/include"
    "${IDF_PATH}/components/esp_phy/esp32c6/include"
    "${IDF_PATH}/components/esp_netif/include"
    "${IDF_PATH}/components/esp_wifi/include"
    "${IDF_PATH}/components/esp_wifi/include/local"
    "${IDF_PATH}/components/esp_wifi/wifi_apps/include"
    "${IDF_PATH}/components/esp_wifi/wifi_apps/nan_app/include"
    # Wendy component headers
    "${CMAKE_CURRENT_LIST_DIR}/../wendy_hal/include"
    "${CMAKE_CURRENT_LIST_DIR}/../wendy_callback/include"
    "${CMAKE_CURRENT_LIST_DIR}/../wendy_sys/include"
    "${CMAKE_CURRENT_LIST_DIR}/../wendy_storage/include"
    "${CMAKE_CURRENT_LIST_DIR}/../wendy_safety/include"
    "${CMAKE_CURRENT_LIST_DIR}/../wendy_uart/include"
    "${CMAKE_CURRENT_LIST_DIR}/../wendy_spi/include"
    "${CMAKE_CURRENT_LIST_DIR}/../wendy_otel/include"
    "${CMAKE_CURRENT_LIST_DIR}/../wendy_ble/include"
    "${CMAKE_CURRENT_LIST_DIR}/../wendy_net/include"
    "${CMAKE_CURRENT_LIST_DIR}/../wendy_app_usb/include"
    # ── RISC-V toolchain stdlib (MUST be last — after ESP-IDF platform wrappers
    # that use #include_next so they find the real newlib headers here) ─────────
    "${SWIFT_RISCV_GCC_INTRINSICS}"
    "${SWIFT_RISCV_LIBC_INCLUDE}"
)

# ── Locate RISC-V toolchain C headers ─────────────────────────────────────────
# _CWasmKit.h includes <stdio.h> which is not provided by ESP-IDF's wrapper
# headers; it lives inside the riscv32-esp-elf GCC/newlib sysroot.

find_program(RISCV_GCC riscv32-esp-elf-gcc)
if(RISCV_GCC)
    # e.g. /path/riscv32-esp-elf/bin/riscv32-esp-elf-gcc
    #  → /path/riscv32-esp-elf/riscv32-esp-elf/include
    get_filename_component(_GCC_BIN_DIR "${RISCV_GCC}" DIRECTORY)
    get_filename_component(_RISCV_ROOT  "${_GCC_BIN_DIR}" DIRECTORY)
    set(SWIFT_RISCV_LIBC_INCLUDE "${_RISCV_ROOT}/riscv32-esp-elf/include")
    # Also keep a reference to the compiler's GCC intrinsic headers (stdint.h etc.)
    set(SWIFT_RISCV_GCC_INCLUDE "${_RISCV_ROOT}/lib/gcc/riscv32-esp-elf")
    file(GLOB _GCC_VER_DIRS "${SWIFT_RISCV_GCC_INCLUDE}/*/include")
    if(_GCC_VER_DIRS)
        list(GET _GCC_VER_DIRS 0 SWIFT_RISCV_GCC_INTRINSICS)
    endif()
    message(STATUS "wendy_wasmkit: RISC-V libc headers at '${SWIFT_RISCV_LIBC_INCLUDE}'")
else()
    message(WARNING "wendy_wasmkit: riscv32-esp-elf-gcc not found; "
        "set SWIFT_RISCV_LIBC_INCLUDE manually if _CWasmKit fails to build")
    set(SWIFT_RISCV_LIBC_INCLUDE "")
endif()

# Build the -Xcc -I arguments list
set(SWIFT_INCLUDE_ARGS "")
foreach(inc ${SWIFT_IDF_INCLUDES})
    list(APPEND SWIFT_INCLUDE_ARGS "-Xcc" "-I${inc}")
endforeach()

# ── Multi-stage Swift compilation ─────────────────────────────────────────────
#
# WasmKit uses separate Swift modules (WasmTypes → WasmParserCore → WasmKit).
# For Embedded Swift we compile them in order, emitting .swiftmodule files so
# each stage can import the previous ones.  Our bridge files are compiled last.
#
# Stage 1: WasmTypes
# Stage 2: WasmParserCore (imports WasmTypes)
# Stage 3: WasmKit        (imports WasmParserCore + WasmTypes)
# Stage 4: WendyWasmKit   (imports WasmKit — our runtime & imports bridge)
# Stage 5: archive all .o into libwendy_wasmkit_swift.a

# Translate Kconfig feature flags into Swift -D defines so that #if CONFIG_WENDY_*
# conditional compilation blocks in WendyImports.swift are evaluated correctly.
# Swift #if only reads -D flags passed to swiftc, not -Xcc -D (which only reach
# the embedded Clang frontend for C imports).
set(SWIFT_KCONFIG_DEFS "")
foreach(_cfg
    CONFIG_WENDY_HAL_GPIO
    CONFIG_WENDY_HAL_I2C
    CONFIG_WENDY_HAL_TIMER
    CONFIG_WENDY_HAL_NEOPIXEL
    CONFIG_WENDY_HAL_RMT
    CONFIG_WENDY_CALLBACK
    CONFIG_WENDY_SYS
    CONFIG_WENDY_STORAGE
    CONFIG_WENDY_UART
    CONFIG_WENDY_SPI
    CONFIG_WENDY_OTEL
    CONFIG_WENDY_WASI_SHIM
    CONFIG_WENDY_BLE
    CONFIG_WENDY_NET
    CONFIG_WENDY_APP_USB
)
    if(${_cfg})
        list(APPEND SWIFT_KCONFIG_DEFS -D ${_cfg})
    endif()
endforeach()

set(SWIFT_BASE_FLAGS
    -enable-experimental-feature Embedded
    -wmo
    -O
    -target riscv32-none-none-eabi
    -Xcc -march=rv32imac
    -Xcc -mabi=ilp32
    # Bare-metal: no dynamic linker — disable PLT/GOT to prevent .got.plt
    # entries that the ESP-IDF linker script would discard, causing link failure.
    -Xcc -fno-pic
    -Xcc -fno-plt
    -Xfrontend -disable-reflection-metadata
    -Xcc -D_REENT_SMALL
    # Required so `package` access level symbols (used throughout WasmKit) are
    # accessible across files within the same Swift package.
    -package-name WasmKit
    # Kconfig feature flags forwarded as Swift compiler defines (see above).
    ${SWIFT_KCONFIG_DEFS}
    # The toolchain's stdlib headers (newlib) and GCC intrinsics must be passed
    # as -isystem so that #include_next in Swift's built-in Clang headers (e.g.
    # inttypes.h) can find the next copy in the system include search path.
    -Xcc -isystem -Xcc "${SWIFT_RISCV_GCC_INTRINSICS}"
    -Xcc -isystem -Xcc "${SWIFT_RISCV_LIBC_INCLUDE}"
    ${SWIFT_INCLUDE_ARGS}
    -Xcc "-fmodule-map-file=${CMAKE_CURRENT_LIST_DIR}/src/module.modulemap"
)

# ── Stage 1: WasmTypes ────────────────────────────────────────────────────────

set(WASMTYPES_OBJ     "${SWIFT_OBJ_DIR}/WasmTypes.o")
set(WASMTYPES_MOD     "${SWIFT_OBJ_DIR}/WasmTypes.swiftmodule")

add_custom_command(
    OUTPUT "${WASMTYPES_OBJ}" "${WASMTYPES_MOD}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${SWIFT_OBJ_DIR}"
    COMMAND "${SWIFTC}" ${SWIFT_BASE_FLAGS}
        -module-name WasmTypes
        -emit-module -emit-module-path "${WASMTYPES_MOD}"
        -emit-object -o "${WASMTYPES_OBJ}"
        ${WASMTYPES_SOURCES}
    DEPENDS ${WASMTYPES_SOURCES}
    COMMENT "[1/4] Swift: WasmTypes"
    VERBATIM
)

# ── Stage 2: WasmParserCore ───────────────────────────────────────────────────

set(WASMPARSER_OBJ    "${SWIFT_OBJ_DIR}/WasmParserCore.o")
set(WASMPARSER_MOD    "${SWIFT_OBJ_DIR}/WasmParserCore.swiftmodule")

add_custom_command(
    OUTPUT "${WASMPARSER_OBJ}" "${WASMPARSER_MOD}"
    COMMAND "${SWIFTC}" ${SWIFT_BASE_FLAGS}
        -module-name WasmParserCore
        -I "${SWIFT_OBJ_DIR}"
        -emit-module -emit-module-path "${WASMPARSER_MOD}"
        -emit-object -o "${WASMPARSER_OBJ}"
        ${WASMPARSER_CORE_SOURCES}
    DEPENDS "${WASMTYPES_OBJ}" "${WASMTYPES_MOD}" ${WASMPARSER_CORE_SOURCES}
    COMMENT "[2/4] Swift: WasmParserCore"
    VERBATIM
)

# ── Stage 3: WasmKit ──────────────────────────────────────────────────────────

set(WASMKIT_OBJ       "${SWIFT_OBJ_DIR}/WasmKit.o")
set(WASMKIT_MOD       "${SWIFT_OBJ_DIR}/WasmKit.swiftmodule")

add_custom_command(
    OUTPUT "${WASMKIT_OBJ}" "${WASMKIT_MOD}"
    COMMAND "${SWIFTC}" ${SWIFT_BASE_FLAGS}
        -module-name WasmKit
        -I "${SWIFT_OBJ_DIR}"
        -emit-module -emit-module-path "${WASMKIT_MOD}"
        -emit-object -o "${WASMKIT_OBJ}"
        ${WASMKIT_ENGINE_SOURCES}
    DEPENDS "${WASMPARSER_OBJ}" "${WASMPARSER_MOD}"
            "${WASMTYPES_OBJ}"  "${WASMTYPES_MOD}"
            ${WASMKIT_ENGINE_SOURCES}
    COMMENT "[3/4] Swift: WasmKit"
    VERBATIM
)

# ── Stage 4: WendyWasmKit bridge ─────────────────────────────────────────────

set(WENDY_OBJ         "${SWIFT_OBJ_DIR}/WendyWasmKit.o")

add_custom_command(
    OUTPUT "${WENDY_OBJ}"
    COMMAND "${SWIFTC}" ${SWIFT_BASE_FLAGS}
        -module-name WendyWasmKit
        -I "${SWIFT_OBJ_DIR}"
        -emit-object -o "${WENDY_OBJ}"
        ${WENDY_SWIFT_SOURCES}
    DEPENDS "${WASMKIT_OBJ}" "${WASMKIT_MOD}" ${WENDY_SWIFT_SOURCES}
    COMMENT "[4/4] Swift: WendyWasmKit (bridge)"
    VERBATIM
)

# ── Stage 5a: Compile C support files ────────────────────────────────────────
# These C files provide symbols referenced by the Swift code but that cannot
# be bundled by idf_component_register's SRCS (wrong toolchain / link order).

# Find ESP-IDF's RISC-V GCC (already used above)
find_program(RISCV_CC riscv32-esp-elf-gcc HINTS ${_GCC_BIN_DIR})
if(NOT RISCV_CC)
    message(WARNING "riscv32-esp-elf-gcc not found; C runtime stubs for WasmKit will be missing")
    set(RISCV_CC "${CMAKE_C_COMPILER}")
endif()

# Common C flags for the bare-metal RISC-V target.
# Uses riscv32-esp-elf-gcc which is already configured for the right target —
# do NOT pass -target (that's a Clang flag; GCC doesn't understand it).
set(WASMKIT_C_FLAGS
    -march=rv32imac
    -mabi=ilp32
    -Os
    -ffunction-sections
    -fdata-sections
    # _Nonnull/_Nullable are Clang extensions; GCC doesn't know them
    -D_Nonnull=
    -D_Nullable=
    -D_Null_unspecified=
)
# Build include flags as separate items (no inner quotes — CMake handles quoting)
list(APPEND WASMKIT_C_FLAGS -I${WASMKIT_ROOT}/Sources/_CWasmKit/include)
list(APPEND WASMKIT_C_FLAGS -I${CMAKE_CURRENT_LIST_DIR}/include)
list(APPEND WASMKIT_C_FLAGS -I${CMAKE_BINARY_DIR}/config)
list(APPEND WASMKIT_C_FLAGS -I${IDF_PATH}/components/newlib/platform_include)
list(APPEND WASMKIT_C_FLAGS -I${IDF_PATH}/components/freertos/config/include)
list(APPEND WASMKIT_C_FLAGS -I${IDF_PATH}/components/freertos/config/include/freertos)
list(APPEND WASMKIT_C_FLAGS -I${IDF_PATH}/components/freertos/config/riscv/include)
list(APPEND WASMKIT_C_FLAGS -I${IDF_PATH}/components/freertos/FreeRTOS-Kernel/include)
list(APPEND WASMKIT_C_FLAGS -I${IDF_PATH}/components/freertos/FreeRTOS-Kernel/portable/riscv/include)
list(APPEND WASMKIT_C_FLAGS -I${IDF_PATH}/components/freertos/FreeRTOS-Kernel/portable/riscv/include/freertos)
list(APPEND WASMKIT_C_FLAGS -I${IDF_PATH}/components/freertos/esp_additions/include)
list(APPEND WASMKIT_C_FLAGS -I${IDF_PATH}/components/esp_common/include)
list(APPEND WASMKIT_C_FLAGS -I${IDF_PATH}/components/esp_hw_support/include)
list(APPEND WASMKIT_C_FLAGS -I${IDF_PATH}/components/riscv/include)
list(APPEND WASMKIT_C_FLAGS -I${IDF_PATH}/components/log/include)
list(APPEND WASMKIT_C_FLAGS -I${IDF_PATH}/components/heap/include)
list(APPEND WASMKIT_C_FLAGS -I${IDF_PATH}/components/soc/include)
list(APPEND WASMKIT_C_FLAGS -I${IDF_PATH}/components/soc/esp32c6/include)
list(APPEND WASMKIT_C_FLAGS -I${IDF_PATH}/components/hal/include)
list(APPEND WASMKIT_C_FLAGS -I${IDF_PATH}/components/hal/esp32c6/include)
list(APPEND WASMKIT_C_FLAGS -I${IDF_PATH}/components/hal/platform_port/include)
list(APPEND WASMKIT_C_FLAGS -I${IDF_PATH}/components/esp_rom/include)
list(APPEND WASMKIT_C_FLAGS -I${IDF_PATH}/components/esp_rom/esp32c6/include)
list(APPEND WASMKIT_C_FLAGS -I${IDF_PATH}/components/esp_partition/include)
list(APPEND WASMKIT_C_FLAGS -I${CMAKE_CURRENT_LIST_DIR}/../wendy_hal/include)
list(APPEND WASMKIT_C_FLAGS -I${CMAKE_CURRENT_LIST_DIR}/../wendy_callback/include)
list(APPEND WASMKIT_C_FLAGS -I${SWIFT_RISCV_GCC_INTRINSICS})
list(APPEND WASMKIT_C_FLAGS -I${SWIFT_RISCV_LIBC_INCLUDE})

set(CWASM_C       "${SWIFT_OBJ_DIR}/_CWasmKit.o")
set(TRAPGUARD_C   "${SWIFT_OBJ_DIR}/TrapGuard.o")
set(BRIDGE_C      "${SWIFT_OBJ_DIR}/WasmKitBridge.o")

add_custom_command(
    OUTPUT "${CWASM_C}"
    COMMAND "${RISCV_CC}" ${WASMKIT_C_FLAGS}
        -c "${WASMKIT_ROOT}/Sources/_CWasmKit/_CWasmKit.c"
        -o "${CWASM_C}"
    DEPENDS "${WASMKIT_ROOT}/Sources/_CWasmKit/_CWasmKit.c"
    COMMENT "Compiling _CWasmKit.c" VERBATIM
)

add_custom_command(
    OUTPUT "${TRAPGUARD_C}"
    COMMAND "${RISCV_CC}" ${WASMKIT_C_FLAGS}
        -c "${WASMKIT_ROOT}/Sources/_CWasmKit/TrapGuard.c"
        -o "${TRAPGUARD_C}"
    DEPENDS "${WASMKIT_ROOT}/Sources/_CWasmKit/TrapGuard.c"
    COMMENT "Compiling TrapGuard.c" VERBATIM
)

add_custom_command(
    OUTPUT "${BRIDGE_C}"
    COMMAND "${RISCV_CC}" ${WASMKIT_C_FLAGS}
        -I${CMAKE_CURRENT_LIST_DIR}/include
        -c "${CMAKE_CURRENT_LIST_DIR}/src/WasmKitBridge.c"
        -o "${BRIDGE_C}"
    DEPENDS "${CMAKE_CURRENT_LIST_DIR}/src/WasmKitBridge.c"
    COMMENT "Compiling WasmKitBridge.c" VERBATIM
)

# ── Stage 5b: Archive ─────────────────────────────────────────────────────────
# Bundle the Swift Unicode data tables into our archive so all symbol references
# are within the same archive, preventing cross-archive PLT stub creation.

set(SWIFT_UNICODE_EMBEDDED_LIB "")
foreach(_candidate
    "$ENV{HOME}/Library/Developer/Toolchains/swift-6.3.1-RELEASE.xctoolchain/usr/lib/swift/embedded/riscv32-none-none-eabi/libswiftUnicodeDataTables.a"
    "$ENV{HOME}/.swiftly/toolchains/swift-6.3.1-RELEASE/usr/lib/swift/embedded/riscv32-none-none-eabi/libswiftUnicodeDataTables.a"
    )
    if(EXISTS "${_candidate}")
        set(SWIFT_UNICODE_EMBEDDED_LIB "${_candidate}")
        break()
    endif()
endforeach()

add_custom_command(
    OUTPUT "${SWIFT_STATIC_LIB}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${SWIFT_OBJ_DIR}/unicode_objs"
    # Extract Unicode data tables .o files into the archive
    COMMAND sh -c "cd '${SWIFT_OBJ_DIR}/unicode_objs' && '${CMAKE_AR}' x '${SWIFT_UNICODE_EMBEDDED_LIB}' 2>/dev/null; true"
    COMMAND "${CMAKE_AR}" rcs "${SWIFT_STATIC_LIB}"
        "${WASMTYPES_OBJ}"
        "${WASMPARSER_OBJ}"
        "${WASMKIT_OBJ}"
        "${WENDY_OBJ}"
        "${CWASM_C}"
        "${TRAPGUARD_C}"
        "${BRIDGE_C}"
    # Append Unicode objects to the archive (*.cpp.o only — *.o would double-add them)
    COMMAND sh -c "for f in '${SWIFT_OBJ_DIR}/unicode_objs'/*.cpp.o; do [ -f \"\$f\" ] && '${CMAKE_AR}' q '${SWIFT_STATIC_LIB}' \"\$f\"; done; true"
    DEPENDS "${WASMTYPES_OBJ}" "${WASMPARSER_OBJ}" "${WASMKIT_OBJ}" "${WENDY_OBJ}"
            "${CWASM_C}" "${TRAPGUARD_C}" "${BRIDGE_C}"
    COMMENT "Archiving WasmKit Embedded Swift library (with Unicode data tables)"
    VERBATIM
)

add_custom_target(wendy_wasmkit_swift_build ALL
    DEPENDS "${SWIFT_STATIC_LIB}"
)

add_dependencies(${COMPONENT_LIB} wendy_wasmkit_swift_build)

# Swift Embedded stdlib for RISC-V: Unicode data tables (required by String).
# swiftly wraps swiftc; the actual toolchain is in ~/Library/Developer/Toolchains.
# We search in the common swiftly install locations and the xctoolchain directory.
set(SWIFT_EMBEDDED_LIB_DIR "")
foreach(_candidate
    "$ENV{HOME}/Library/Developer/Toolchains/swift-6.3.1-RELEASE.xctoolchain/usr/lib/swift/embedded/riscv32-none-none-eabi"
    "$ENV{HOME}/.swiftly/toolchains/swift-6.3.1-RELEASE/usr/lib/swift/embedded/riscv32-none-none-eabi"
    "$ENV{HOME}/.swiftpm/swift-sdks/embedded/riscv32-none-none-eabi"
    )
    if(EXISTS "${_candidate}/libswiftUnicodeDataTables.a")
        set(SWIFT_EMBEDDED_LIB_DIR "${_candidate}")
        break()
    endif()
endforeach()
set(SWIFT_UNICODE_LIB
    "${SWIFT_EMBEDDED_LIB_DIR}/libswiftUnicodeDataTables.a")
if(NOT EXISTS "${SWIFT_UNICODE_LIB}")
    message(WARNING "libswiftUnicodeDataTables.a not found at '${SWIFT_UNICODE_LIB}'; "
        "Unicode normalization functions may fail to link.")
else()
    message(STATUS "wendy_wasmkit: Swift Unicode lib at '${SWIFT_UNICODE_LIB}'")
endif()

# INTERFACE because idf_component_register(SRCS "") creates an INTERFACE target.
# Unicode tables are now bundled inside SWIFT_STATIC_LIB (see archive step above).
# The Swift archive (WendyWasmKit.o) directly calls HAL C functions (e.g.
# wendy_hal_gpio_configure) at link time.  Because the Swift archive appears AFTER
# the HAL component libraries in the link order, GNU ld cannot resolve these forward
# references unless we wrap the relevant archives in --start-group / --end-group.
set(_HAL_LIB        "${CMAKE_BINARY_DIR}/esp-idf/wendy_hal/libwendy_hal.a")
set(_LED_STRIP_LIB  "${CMAKE_BINARY_DIR}/esp-idf/espressif__led_strip/libespressif__led_strip.a")
set(_CALLBACK_LIB   "${CMAKE_BINARY_DIR}/esp-idf/wendy_callback/libwendy_callback.a")
set(_SYS_LIB        "${CMAKE_BINARY_DIR}/esp-idf/wendy_sys/libwendy_sys.a")
set(_STORAGE_LIB    "${CMAKE_BINARY_DIR}/esp-idf/wendy_storage/libwendy_storage.a")
set(_UART_LIB       "${CMAKE_BINARY_DIR}/esp-idf/wendy_uart/libwendy_uart.a")
set(_SPI_LIB        "${CMAKE_BINARY_DIR}/esp-idf/wendy_spi/libwendy_spi.a")
set(_OTEL_LIB       "${CMAKE_BINARY_DIR}/esp-idf/wendy_otel/libwendy_otel.a")
target_link_libraries(${COMPONENT_LIB} INTERFACE
    -Wl,--start-group
        "${SWIFT_STATIC_LIB}"
        "${_HAL_LIB}"
        "${_LED_STRIP_LIB}"
        "${_CALLBACK_LIB}"
        "${_SYS_LIB}"
        "${_STORAGE_LIB}"
        "${_UART_LIB}"
        "${_SPI_LIB}"
        "${_OTEL_LIB}"
    -Wl,--end-group
)

# The Swift/RISC-V LLVM backend can produce an empty .got.plt section due to
# R_RISCV_CALL_PLT relocations.  ESP-IDF's /DISCARD/ rule would discard it, but
# with --orphan-handling=warn (the ESP-IDF default), an orphan .got.plt that was
# placed then discarded triggers "discarded output section" → "final link failed".
# Override with --orphan-handling=discard so orphan sections are silently dropped.
target_link_options(${COMPONENT_LIB} INTERFACE
    -Wl,--orphan-handling=discard
)
