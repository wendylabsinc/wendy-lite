set(requires wendy_wasm wendy_hal wendy_hal_export)

if(CONFIG_WENDY_USB_CDC_ENABLED)
    list(APPEND requires wendy_usb)
endif()

idf_component_register(
    SRCS "wendy_main.c"
    INCLUDE_DIRS "."
    REQUIRES ${requires} nvs_flash esp_partition
)
