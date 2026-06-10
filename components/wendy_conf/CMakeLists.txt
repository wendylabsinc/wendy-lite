idf_component_register(
    SRCS
        "src/wendy_conf.c"
        "src/wendy_conf.pb.c"
    INCLUDE_DIRS
        "include"
    REQUIRES
        esp_partition log
        nanopb
)
