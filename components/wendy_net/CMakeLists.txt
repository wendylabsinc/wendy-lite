set(requires wasm-micro-runtime esp_wifi esp_netif lwip vfs wendy_safety wendy_callback)

set(srcs "")

if(CONFIG_WENDY_NET)
    list(APPEND srcs "src/wendy_net.c")
endif()

if(NOT srcs)
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/wendy_net_stub.c" "/* wendy_net disabled */\n")
    list(APPEND srcs "${CMAKE_CURRENT_BINARY_DIR}/wendy_net_stub.c")
endif()

idf_component_register(
    SRCS ${srcs}
    INCLUDE_DIRS "include"
    REQUIRES ${requires}
)
