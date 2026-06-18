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
    SRCS "src/WasmKitBridge.c"
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
        wendy_wasi_shim
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

# WasmParserCore
file(GLOB WASMPARSER_CORE_SOURCES
    "${WASMKIT_ROOT}/Sources/WasmParserCore/*.swift"
    "${WASMKIT_ROOT}/Sources/WasmParserCore/Stream/*.swift"
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
    "${WASMKIT_ROOT}/Sources/WasmKit/BinaryInstructionDecoder.swift"
    "${WASMKIT_ROOT}/Sources/WasmKit/InstructionVisitor.swift"
    "${WASMKIT_ROOT}/Sources/WasmKit/Execution/AtomicParkingLot.swift"
    "${WASMKIT_ROOT}/Sources/WasmKit/Execution/DispatchInstruction.swift"
    "${WASMKIT_ROOT}/Sources/WasmKit/Execution/Errors.swift"
    "${WASMKIT_ROOT}/Sources/WasmKit/Execution/Execution.swift"
    "${WASMKIT_ROOT}/Sources/WasmKit/Execution/Function.swift"
    "${WASMKIT_ROOT}/Sources/WasmKit/Execution/Instances.swift"
    "${WASMKIT_ROOT}/Sources/WasmKit/Execution/ConstEvaluation.swift"
    "${WASMKIT_ROOT}/Sources/WasmKit/Execution/IO.swift"
    "${WASMKIT_ROOT}/Sources/WasmKit/Execution/NameRegistry.swift"
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
    "${CMAKE_CURRENT_LIST_DIR}/src/Runtime.swift"
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

# The _CWasmKit C header is included via a module map in the WasmKit tree.
# We also need the wendy HAL and ESP-IDF system headers.
set(SWIFT_IDF_INCLUDES
    # WasmKit internal C shim
    "${WASMKIT_ROOT}/Sources/_CWasmKit/include"
    # IDF core
    "${IDF_PATH}/components/freertos/FreeRTOS-Kernel/include"
    "${IDF_PATH}/components/freertos/FreeRTOS-Kernel/portable/riscv/include"
    "${IDF_PATH}/components/freertos/esp_additions/include"
    "${IDF_PATH}/components/freertos/FreeRTOS-Kernel/include/freertos"
    "${IDF_PATH}/components/esp_common/include"
    "${IDF_PATH}/components/esp_hw_support/include"
    "${IDF_PATH}/components/esp_partition/include"
    "${IDF_PATH}/components/heap/include"
    "${IDF_PATH}/components/log/include"
    "${IDF_PATH}/components/soc/esp32c6/include"
    "${IDF_PATH}/components/soc/include"
    "${IDF_PATH}/components/hal/esp32c6/include"
    "${IDF_PATH}/components/hal/include"
    "${IDF_PATH}/components/hal/platform_port/include"
    "${IDF_PATH}/components/esp_rom/include"
    "${IDF_PATH}/components/esp_rom/esp32c6/include"
    "${IDF_PATH}/components/riscv/include"
    "${IDF_PATH}/components/newlib/platform_include"
    "${IDF_PATH}/components/nvs_flash/include"
    "${IDF_PATH}/components/esp_partition/include"
    "${IDF_PATH}/components/driver/gpio/include"
    "${IDF_PATH}/components/driver/i2c/include"
    "${IDF_PATH}/components/driver/uart/include"
    "${IDF_PATH}/components/driver/spi_master/include"
    "${IDF_PATH}/components/driver/rmt/include"
    "${IDF_PATH}/components/driver/ledc/include"
    "${IDF_PATH}/components/esp_adc/include"
    # Generated sdkconfig
    "${CMAKE_BINARY_DIR}/config"
    # Wendy HAL + component headers (resolved via build system)
    "${CMAKE_CURRENT_LIST_DIR}/../wendy_hal/include"
    "${CMAKE_CURRENT_LIST_DIR}/../wendy_callback/include"
    "${CMAKE_CURRENT_LIST_DIR}/../wendy_sys/include"
    "${CMAKE_CURRENT_LIST_DIR}/../wendy_storage/include"
    "${CMAKE_CURRENT_LIST_DIR}/../wendy_uart/include"
    "${CMAKE_CURRENT_LIST_DIR}/../wendy_spi/include"
    "${CMAKE_CURRENT_LIST_DIR}/../wendy_otel/include"
    "${CMAKE_CURRENT_LIST_DIR}/../wendy_wasi_shim/include"
    "${CMAKE_CURRENT_LIST_DIR}/../wendy_ble/include"
    "${CMAKE_CURRENT_LIST_DIR}/../wendy_net/include"
    "${CMAKE_CURRENT_LIST_DIR}/../wendy_app_usb/include"
)

# Build the -Xcc -I arguments list
set(SWIFT_INCLUDE_ARGS "")
foreach(inc ${SWIFT_IDF_INCLUDES})
    list(APPEND SWIFT_INCLUDE_ARGS "-Xcc" "-I${inc}")
endforeach()

# ── Custom Swift compilation command ──────────────────────────────────────────

add_custom_command(
    OUTPUT "${SWIFT_STATIC_LIB}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${SWIFT_OBJ_DIR}"
    COMMAND
        "${SWIFTC}"
        # Embedded Swift flags
        -enable-experimental-feature Embedded
        -wmo
        -O
        # Target: RISC-V 32-bit bare metal (ESP32-C6 = rv32imac)
        -target riscv32-none-none-eabi
        -Xcc -march=rv32imc
        -Xcc -mabi=ilp32
        # Suppress unavailable platform warnings (no OS platform for embedded)
        -Xfrontend -disable-reflection-metadata
        # Module name for the combined unit
        -module-name WendyWasmKit
        # Let WasmKit know it's compiling in embedded mode
        # (WasmKit detects #if $Embedded automatically via the flag above)
        # IDF + HAL include paths
        ${SWIFT_INCLUDE_ARGS}
        # The C module map so Swift can import _CWasmKit and WendyC
        -Xcc "-fmodule-map-file=${CMAKE_CURRENT_LIST_DIR}/src/module.modulemap"
        # All Swift sources (WMO compiles them as one unit)
        ${ALL_SWIFT_SOURCES}
        # Output: static archive
        -emit-object -o "${SWIFT_OBJ_DIR}/wendy_wasmkit_swift.o"
    COMMAND
        "${CMAKE_AR}" rcs "${SWIFT_STATIC_LIB}"
        "${SWIFT_OBJ_DIR}/wendy_wasmkit_swift.o"
    DEPENDS ${ALL_SWIFT_SOURCES}
    COMMENT "Compiling WasmKit Embedded Swift sources for ${IDF_TARGET}"
    VERBATIM
)

add_custom_target(wendy_wasmkit_swift_build ALL
    DEPENDS "${SWIFT_STATIC_LIB}"
)

add_dependencies(${COMPONENT_LIB} wendy_wasmkit_swift_build)

target_link_libraries(${COMPONENT_LIB} PUBLIC "${SWIFT_STATIC_LIB}")
