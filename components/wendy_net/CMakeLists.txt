set(requires wasm-micro-runtime esp_wifi esp_netif lwip wendy_safety wendy_callback)

idf_component_register(
    SRCS "src/wendy_net.c"
    INCLUDE_DIRS "include"
    REQUIRES ${requires}
)
