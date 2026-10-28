set(requires wendy_net_common wasm-micro-runtime esp_wifi esp_netif esp_timer lwip vfs wendy_safety wendy_callback wendy_wifi wendy_wasm)

set(srcs "")
if(CONFIG_WENDY_NET)
    list(APPEND srcs "src/wendy_net.c" "src/raw.c")
endif()

idf_component_register(
    SRCS ${srcs}
    INCLUDE_DIRS "include"
    REQUIRES ${requires}
)
