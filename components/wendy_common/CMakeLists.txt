idf_component_register(
    SRCS "src/wendy_common.c" "src/u2_json.c"
    INCLUDE_DIRS "include"
    REQUIRES vfs log
)
