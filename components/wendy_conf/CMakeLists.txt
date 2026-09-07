idf_component_register(
    SRCS
        "src/wendy_conf.c"
        "src/wendy_conf.pb.c"
    INCLUDE_DIRS
        "include"
    EMBED_FILES
        "certs/default_cert.der"
        "certs/default_key.der"
    REQUIRES
        esp_partition log
        nanopb
)
