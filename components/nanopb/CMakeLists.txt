# nanopb runtime — source files are populated by tools/update_protobuf.py
idf_component_register(
    SRCS
        "pb_common.c"
        "pb_encode.c"
        "pb_decode.c"
    INCLUDE_DIRS
        "."
)
