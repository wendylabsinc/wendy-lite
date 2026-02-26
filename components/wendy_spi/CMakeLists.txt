idf_component_register(
    SRCS "src/wendy_spi.c"
    INCLUDE_DIRS "include"
    REQUIRES wasm-micro-runtime driver wendy_safety
)
