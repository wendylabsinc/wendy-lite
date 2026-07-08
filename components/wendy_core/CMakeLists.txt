idf_component_register(
    SRCS "src/wendy_core.c"
    INCLUDE_DIRS "include"
    REQUIRES wendy_conf wendy_usb wendy_usj wendy_wifi wendy_ble_prov wendy_cloud_prov nvs_flash esp_partition esp_netif app_update
)
