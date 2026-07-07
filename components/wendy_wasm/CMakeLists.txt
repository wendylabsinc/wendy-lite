set(srcs "")

if(CONFIG_WENDY_WASM)
    list(APPEND srcs "src/wendy_wasm.c")
endif()

if(NOT srcs)
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/wendy_wasm_stub.c" "/* WASM disabled */\n")
    list(APPEND srcs "${CMAKE_CURRENT_BINARY_DIR}/wendy_wasm_stub.c")
endif()

idf_component_register(
    SRCS ${srcs}
    INCLUDE_DIRS "include"
    REQUIRES esp_partition spi_flash
)
