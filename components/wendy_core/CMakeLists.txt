idf_build_get_property(target IDF_TARGET)

set(requires wendy_conf wendy_stdio wendy_usb wendy_usj wendy_wifi wendy_ble_prov wendy_cloud_prov nvs_flash esp_partition esp_netif app_update)

# wendy_wasm/wendy_hal/wendy_hal_export are resolved by the component
# manager for every target except esp32c61 (see the "target != esp32c61"
# rules in idf_component.yml — no published WAMR release supports esp32c61
# yet). REQUIRES must mirror that exactly with a build-system-level target
# check, not a Kconfig value: REQUIRES is evaluated before Kconfig exists,
# so a component excluded by the manifest but still listed here fails with
# "component not found", and one included by the manifest but omitted here
# fails wendy_core.c's #include "wendy_wasm.h".
if(NOT target STREQUAL "esp32c61")
    list(APPEND requires wendy_wasm wendy_hal wendy_hal_export)
endif()

idf_component_register(
    SRCS "src/wendy_core.c"
    INCLUDE_DIRS "include"
    REQUIRES ${requires}
)
