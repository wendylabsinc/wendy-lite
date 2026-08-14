set(srcs "")

if(CONFIG_WENDY_WIFI_ENABLED)
    list(APPEND srcs "src/wendy_wifi.c")
endif()

if(NOT srcs)
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/wendy_wifi_stub.c" "/* WiFi disabled */\n")
    list(APPEND srcs "${CMAKE_CURRENT_BINARY_DIR}/wendy_wifi_stub.c")
endif()

idf_component_register(
    SRCS ${srcs}
    INCLUDE_DIRS "include"
    REQUIRES esp_wifi esp_netif esp_event mdns lwip freertos nvs_flash esp_partition wendy_com wendy_server wendy_cloud wendy_conf
)
