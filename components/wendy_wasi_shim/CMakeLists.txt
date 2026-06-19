idf_component_register(
    SRCS "src/wendy_wasi_shim.c"
    INCLUDE_DIRS "include"
    REQUIRES wendy_wasmkit esp_timer wendy_safety
)
