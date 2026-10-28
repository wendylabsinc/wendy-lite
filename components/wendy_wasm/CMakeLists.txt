idf_component_register(
    SRCS "src/wendy_wasm.c" "src/memory_limit.c" "src/linear_replacement.c"
    INCLUDE_DIRS "include"
    REQUIRES wasm-micro-runtime esp_partition spi_flash
)
