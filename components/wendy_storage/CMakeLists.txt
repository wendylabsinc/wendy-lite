idf_component_register(
    SRCS "src/wendy_storage.c"
    INCLUDE_DIRS "include"
    REQUIRES wasm-micro-runtime nvs_flash wendy_safety
)
