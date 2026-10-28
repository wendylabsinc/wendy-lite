idf_component_register(
    SRCS
        "src/wendy_server.c"
        "src/wendy_server_tls.c"
    INCLUDE_DIRS
        "include"
    PRIV_REQUIRES wendy_net_peer
    REQUIRES
        wendy_com wendy_conf wendy_pki esp-tls freertos log mdns esp_timer mbedtls
)
