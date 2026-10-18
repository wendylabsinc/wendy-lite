idf_component_register(
    SRCS "src/wendy_spi.c"
    INCLUDE_DIRS "include"
    REQUIRES wasm-micro-runtime esp_driver_spi wendy_safety
)
