idf_component_register(
    SRCS "dashboard.c" "diagnostics.c" "usb_management.c"
    INCLUDE_DIRS "."
    PRIV_REQUIRES
        esp-mosaico-bsp
        espressif__esp_tinyusb
        wendy_com
        wendy_stdio
        wendy_net_peer
        wendy_core
        wendy_sensor_link
        wendy_conf
        wendy_wifi
        wendy_cloud
        wendy_pki
        esp_timer
        esp_system
        esp_rom
        espcoredump
        esp_app_format
        app_update
        heap
)
