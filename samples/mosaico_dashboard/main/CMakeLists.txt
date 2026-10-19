idf_component_register(
    SRCS "dashboard.c" "diagnostics.c" "usb_management.c"
    INCLUDE_DIRS "."
    PRIV_REQUIRES
        esp-mosaico-bsp
        espressif__esp_tinyusb
        wendy_com
        wendy_stdio
        wendy_mesh
        wendy_core
        wendy_conf
        wendy_wifi
        wendy_cloud
        wendy_pki
        esp_timer
        esp_system
        espcoredump
        esp_app_format
        app_update
        heap
)
