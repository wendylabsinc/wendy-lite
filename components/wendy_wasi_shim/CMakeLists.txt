idf_component_register(
    SRCS "src/wendy_wasi_shim.c"
    INCLUDE_DIRS "include"
    REQUIRES wasm-micro-runtime wendy_safety
)
