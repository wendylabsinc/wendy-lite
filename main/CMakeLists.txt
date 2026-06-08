idf_component_register(
    SRCS "wendy_main.c"
    INCLUDE_DIRS "."
    REQUIRES wendy_wasm wendy_hal wendy_hal_export wendy_usb wendy_wifi wendy_ble_prov wendy_cloud_prov nvs_flash esp_partition esp_netif
)
