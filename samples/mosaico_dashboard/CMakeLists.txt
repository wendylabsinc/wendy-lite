cmake_minimum_required(VERSION 3.29)

get_filename_component(WENDY_LITE_ROOT "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
set(IDF_TARGET "esp32s31" CACHE STRING "Mosaico target")
if(NOT IDF_TARGET STREQUAL "esp32s31")
    message(FATAL_ERROR "The Mosaico dashboard requires ESP32-S31")
endif()
set(SDKCONFIG_DEFAULTS "${WENDY_LITE_ROOT}/sdkconfig.defaults;${CMAKE_CURRENT_LIST_DIR}/sdkconfig.defaults")

if(WENDY_VERSION_DEFAULTS)
    list(APPEND SDKCONFIG_DEFAULTS "${WENDY_VERSION_DEFAULTS}")
endif()

set(CMAKE_POLICY_VERSION_MINIMUM 3.5)
set(EXTRA_COMPONENT_DIRS "${WENDY_LITE_ROOT}/components")
# S31 is native-only until the pinned WAMR release supports it.
set(EXCLUDE_COMPONENTS
    wendy_benchmark wendy_sensor_link wendy_display wendy_mosaico
    wendy_wasm wendy_hal wendy_hal_export wendy_app_usb wendy_ble_export
    wendy_callback wendy_safety wendy_storage wendy_net wendy_sys
    wendy_spi wendy_otel wendy_wasi_shim wendy_uart)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
idf_build_set_property(MINIMAL_BUILD ON)
project(mosaico_dashboard)

# Apply the same reviewed TLS fixes as the main firmware.
include("${WENDY_LITE_ROOT}/cmake/dependency_patches.cmake")
if(NOT CONFIG_MBEDTLS_USE_BUNDLED_PQC OR CONFIG_MBEDTLS_DYNAMIC_BUFFER)
    message(FATAL_ERROR "The dashboard requires esp-pqc with fixed TLS receive buffers. Configure a fresh sdkconfig.")
endif()
wendy_patch_mbedtls("${WENDY_LITE_ROOT}/components/esp-pqc/components/mbedtls/mbedtls")
