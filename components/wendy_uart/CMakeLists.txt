set(requires wendy_wasmkit driver wendy_callback)

idf_component_register(
    SRCS "src/wendy_uart.c"
    INCLUDE_DIRS "include"
    REQUIRES ${requires}
)
