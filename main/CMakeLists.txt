idf_component_register(
    SRCS "wendy_main.c"
    INCLUDE_DIRS "."
    REQUIRES wendy_wasm wendy_hal wendy_hal_export wendy_usb wendy_wifi nvs_flash esp_partition
)
