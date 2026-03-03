set(srcs "")

if(CONFIG_WENDY_CLOUD_PROV)
    list(APPEND srcs "src/wendy_cloud_prov.c")
endif()

if(NOT srcs)
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/wendy_cloud_prov_stub.c" "/* Cloud prov disabled */\n")
    list(APPEND srcs "${CMAKE_CURRENT_BINARY_DIR}/wendy_cloud_prov_stub.c")
endif()

idf_component_register(
    SRCS ${srcs}
    INCLUDE_DIRS "include"
    REQUIRES bt nvs_flash freertos
)
