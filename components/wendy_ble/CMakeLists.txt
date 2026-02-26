set(requires wasm-micro-runtime wendy_safety wendy_callback)

idf_component_register(
    SRCS "src/wendy_ble.c"
    INCLUDE_DIRS "include"
    REQUIRES ${requires}
)
