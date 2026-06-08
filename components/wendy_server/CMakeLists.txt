idf_component_register(
    SRCS
        "src/wendy_server.c"
    INCLUDE_DIRS
        "include"
    REQUIRES
        wendy_com esp-tls freertos log mdns wendy_common
)
