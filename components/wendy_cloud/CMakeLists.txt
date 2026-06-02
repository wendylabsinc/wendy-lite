set(srcs "")

if(CONFIG_WENDY_CLOUD_ENABLED)
    list(APPEND srcs "src/wendy_cloud.c")
endif()

if(NOT srcs)
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/wendy_cloud_stub.c" "/* Cloud disabled */\n")
    list(APPEND srcs "${CMAKE_CURRENT_BINARY_DIR}/wendy_cloud_stub.c")
endif()

idf_component_register(
    SRCS ${srcs}
    INCLUDE_DIRS "include"
    EMBED_TXTFILES "certs/provisioning.json"
    REQUIRES esp-tls freertos wendy_common
)
