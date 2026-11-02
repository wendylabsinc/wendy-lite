idf_component_register(SRCS "src/protocol.c" "src/binary.c" "src/packet.c" "src/directory.c" "src/manifest_service.c" "src/service_protocol.c" "src/guest_json.c" "src/certificate_fetch.c" "src/certificate_store.c" "src/certificate_wire.c"
    INCLUDE_DIRS "include" PRIV_INCLUDE_DIRS "src"
    REQUIRES wendy_net_common wendy_pki wendy_conf lwip espressif__cjson)
