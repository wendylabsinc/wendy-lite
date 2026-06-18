idf_component_register(
    SRCS "src/wendy_spi.c"
    INCLUDE_DIRS "include"
    REQUIRES wendy_wasmkit driver wendy_safety
)
