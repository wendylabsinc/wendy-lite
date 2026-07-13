idf_component_register(
    SRCS
        "src/wendy_com.c"
        "src/wendy_com_agent.c"
        "src/wendy_com_cmd.c"
        "src/wendy_com_stdio.c"
        "src/wendy_com_stdio_pump.c"
        "src/wendy_com_link.c"
        "src/wendy_com_uart.c"
        "src/wendy_com_msg.pb.c"
    INCLUDE_DIRS
        "include"
    REQUIRES
        esp-tls mbedtls freertos vfs log
        nanopb wendy_stdio esp_timer
)
idf_component_get_property(nanopb_dir nanopb COMPONENT_DIR)
target_include_directories(${COMPONENT_LIB} PUBLIC "${nanopb_dir}")
