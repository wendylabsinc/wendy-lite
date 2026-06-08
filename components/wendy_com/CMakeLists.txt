idf_component_register(
    SRCS
        "src/wendy_com.c"
        "src/wendy_com_agent.c"
        "src/wendy_com_cmd.c"
        "src/wendy_com_link.c"
        "src/wendy_com_msg.pb.c"
    INCLUDE_DIRS
        "include"
    REQUIRES
        esp-tls mbedtls freertos vfs log
        wendy_common
        nanopb
)
