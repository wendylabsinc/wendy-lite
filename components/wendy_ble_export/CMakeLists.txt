idf_component_register(
    SRCS "src/wendy_ble_export.c"
    INCLUDE_DIRS "include"
    REQUIRES wasm-micro-runtime wendy_safety wendy_callback wendy_ble bt
)
