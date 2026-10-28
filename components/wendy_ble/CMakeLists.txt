set(wendy_ble_sources "src/wendy_ble.c")
if(CONFIG_WENDY_BLE)
    list(APPEND wendy_ble_sources "src/wendy_ble_l2cap.c" "src/wendy_ble_tls.c")
    if(CONFIG_WENDY_BLE_SETUP)
        list(APPEND wendy_ble_sources "src/wendy_ble_setup.c" "src/wendy_ble_setup_crypto.c"
            "src/wendy_ble_setup_dispatch.c" "src/wendy_ble_setup_wire.c" "src/wendy_ble_setup.pb.c")
    endif()
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
        wendy_com wendy_conf wendy_pki wendy_wifi nanopb esp_timer
    PRIV_REQUIRES ${wendy_ble_mesh_requires}
)
