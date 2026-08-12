set(requires wasm-micro-runtime esp_wifi esp_netif lwip vfs wendy_safety wendy_callback)

set(srcs "")
if(CONFIG_WENDY_NET)
    list(APPEND srcs "src/wendy_net.c")
endif()

idf_component_register(
    SRCS ${srcs}
    INCLUDE_DIRS "include"
    REQUIRES ${requires}
)
