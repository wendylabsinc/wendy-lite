set(wendy_ble_sources "src/wendy_ble.c")
if(CONFIG_WENDY_BLE)
    list(APPEND wendy_ble_sources "src/wendy_ble_l2cap.c" "src/wendy_ble_tls.c")
endif()
if(CONFIG_WENDY_NET_BLE)
    list(APPEND wendy_ble_sources "src/wendy_ble_mesh.c")
    set(wendy_ble_mesh_requires "wendy_net_common")
endif()

idf_component_register(
    SRCS ${wendy_ble_sources}
    INCLUDE_DIRS
        "include"
    PRIV_INCLUDE_DIRS
        "src"
    REQUIRES
        bt mbedtls freertos log
        wendy_com wendy_conf wendy_pki
    PRIV_REQUIRES ${wendy_ble_mesh_requires}
)
