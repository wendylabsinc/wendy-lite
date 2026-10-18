idf_component_register(
    SRCS "dashboard.c"
    INCLUDE_DIRS "."
    PRIV_REQUIRES
        esp-mosaico-bsp
        wendy_core
        wendy_conf
        wendy_wifi
        wendy_cloud
        wendy_pki
        esp_timer
        esp_system
        heap
)
