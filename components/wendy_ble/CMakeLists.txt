idf_component_register(
    SRCS "src/wendy_ble.c"
    INCLUDE_DIRS "include"
    REQUIRES wasm-micro-runtime wendy_safety wendy_callback bt
    PRIV_REQUIRES wendy_ble_prov
)
