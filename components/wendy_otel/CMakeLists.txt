idf_component_register(
    SRCS "src/wendy_otel.c"
    INCLUDE_DIRS "include"
    REQUIRES wendy_wasmkit
)
