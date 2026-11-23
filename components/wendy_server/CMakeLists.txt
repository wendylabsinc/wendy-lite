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

# wendy_server, wendy_net_peer, wendy_wifi and wendy_cloud depend on each other
# in a loop. CMake repeats a loop 2 times in the link line, which is not enough
# when an app reaches it through wendy_wifi. Use 3, as ESP-IDF does for
# esp_common (4) and wpa_supplicant (3). This is a minimal fix: WDY-4355 removes
# the loop (wendy_wifi will no longer start the server and the cloud).
set_property(TARGET ${COMPONENT_LIB} APPEND PROPERTY LINK_INTERFACE_MULTIPLICITY 3)
