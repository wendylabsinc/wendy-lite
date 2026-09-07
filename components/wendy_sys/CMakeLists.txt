set(requires wasm-micro-runtime esp_timer wendy_callback wendy_wasm wendy_conf)

idf_component_register(
    SRCS "src/wendy_sys.c"
    INCLUDE_DIRS "include"
    REQUIRES ${requires}
)
