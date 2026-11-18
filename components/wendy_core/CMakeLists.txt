idf_component_register(
    SRCS "src/wendy_core.c" "src/wendy_core_sensor.c" "src/wendy_core_wdt.c"
    INCLUDE_DIRS "include"
    REQUIRES wendy_conf wendy_stdio wendy_usj wendy_wifi wendy_ble nvs_flash esp_partition app_update
    PRIV_REQUIRES esp_hal_wdt
)

# COMPONENT_VERSION is set by the IDF Component Manager from the top-level
# `version:` field of idf_component.yml. It is the empty string when the
# manifest declares no version.
idf_component_get_property(wendy_core_version wendy_core COMPONENT_VERSION)
target_compile_definitions(${COMPONENT_LIB} PRIVATE
    WENDY_CORE_COMPONENT_VERSION="${wendy_core_version}")

# Fail the configure step if the PSRAM throughput profile is enabled with
# unsupported or stale settings. It is here, not in the top-level
# CMakeLists.txt, so that native apps (which use wendy_core) also run it.
include("${CMAKE_CURRENT_LIST_DIR}/network_profile.cmake")
wendy_check_network_profile()
