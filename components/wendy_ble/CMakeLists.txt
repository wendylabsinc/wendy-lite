idf_component_register(
    SRCS
        "src/wendy_ble.c"
        "src/wendy_ble_l2cap.c"
        "src/wendy_ble_tls.c"
    INCLUDE_DIRS
        "include"
    PRIV_INCLUDE_DIRS
        "src"
    REQUIRES
        bt mbedtls freertos log
        wendy_com wendy_conf
)
