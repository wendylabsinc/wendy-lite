set(requires wendy_wasmkit esp_timer wendy_callback wendy_wasm)

idf_component_register(
    SRCS "src/wendy_sys.c"
    INCLUDE_DIRS "include"
    REQUIRES ${requires}
)
