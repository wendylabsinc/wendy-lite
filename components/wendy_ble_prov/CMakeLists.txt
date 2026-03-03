set(srcs "")

if(CONFIG_WENDY_BLE_PROV)
    list(APPEND srcs "src/wendy_ble_prov.c")
endif()

if(NOT srcs)
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/wendy_ble_prov_stub.c" "/* BLE prov disabled */\n")
    list(APPEND srcs "${CMAKE_CURRENT_BINARY_DIR}/wendy_ble_prov_stub.c")
endif()

idf_component_register(
    SRCS ${srcs}
    INCLUDE_DIRS "include"
    REQUIRES bt nvs_flash freertos esp_event wendy_cloud_prov
)
