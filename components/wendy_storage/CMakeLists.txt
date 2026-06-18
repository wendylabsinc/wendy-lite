idf_component_register(
    SRCS "src/wendy_storage.c"
    INCLUDE_DIRS "include"
    REQUIRES wendy_wasmkit nvs_flash wendy_safety
)
