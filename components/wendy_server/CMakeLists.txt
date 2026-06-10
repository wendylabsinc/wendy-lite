idf_component_register(
    SRCS
        "src/wendy_server.c"
    INCLUDE_DIRS
        "include"
    EMBED_FILES
        "certs/default_cert.der"
        "certs/default_key.der"
    REQUIRES
        wendy_com wendy_conf esp-tls freertos log mdns wendy_common
)
