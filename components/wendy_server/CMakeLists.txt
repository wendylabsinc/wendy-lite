if(CONFIG_WENDY_NET_PEER)
 set(native_server_requires wendy_net_peer)
endif()
idf_component_register(
    SRCS
        "src/wendy_server.c"
        "src/wendy_server_tls.c"
    INCLUDE_DIRS
        "include"
    PRIV_REQUIRES ${native_server_requires}
    REQUIRES
        wendy_com wendy_conf wendy_pki esp-tls freertos log mdns esp_timer mbedtls
)
