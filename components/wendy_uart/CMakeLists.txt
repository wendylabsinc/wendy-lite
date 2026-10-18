set(requires wasm-micro-runtime esp_driver_uart wendy_callback)

idf_component_register(
    SRCS "src/wendy_uart.c"
    INCLUDE_DIRS "include"
    REQUIRES ${requires}
)
