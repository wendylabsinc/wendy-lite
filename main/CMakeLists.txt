idf_component_register(
    SRCS "wendy_main.c"
    INCLUDE_DIRS "."
    # jo/wasmkit-runtime: wendy_wasm replaced by wendy_wasmkit
    REQUIRES wendy_conf wendy_wasmkit wendy_hal wendy_hal_export wendy_usb wendy_wifi wendy_ble_prov wendy_cloud_prov nvs_flash esp_partition esp_netif
)
