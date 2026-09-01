idf_component_register(
    SRCS "src/wendy_core.c"
    INCLUDE_DIRS "include"
    REQUIRES wendy_conf wendy_stdio wendy_usj wendy_wifi wendy_ble nvs_flash esp_partition app_update
)
