idf_component_register(
    SRCS "src/wendy_core.c"
    INCLUDE_DIRS "include"
    REQUIRES wendy_conf wendy_stdio wendy_usj wendy_wifi nvs_flash esp_partition app_update
)
