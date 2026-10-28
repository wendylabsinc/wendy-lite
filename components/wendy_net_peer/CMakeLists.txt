set(native_driver_sources)
if(CONFIG_WENDY_NET_PEER)
 list(APPEND native_driver_sources "src/peer.c" "src/actor.c" "src/actor_driver.c" "src/selection.c" "src/ble_protocol.c" "src/carrier.c" "src/packet_queue.c" "src/netif_effect.c" "src/mdns_effect.c" "src/time_control.c" "src/nan_protocol.c" "src/settings.c")
endif()
idf_component_register(SRCS ${native_driver_sources} "src/router.c" "src/control.c" "src/router_session.c" "src/crypto_job.c" "src/certificate_worker.c" "src/certificate_read.c" "src/catalog_node.c" "src/manifest_catalog.c" "src/catalog_guest.c" "src/service_store.c" "src/native_staging.c" "src/protocol.c" "src/binary.c" "src/packet.c" "src/directory.c" "src/manifest_service.c" "src/service_protocol.c" "src/guest_json.c" "src/certificate_fetch.c" "src/certificate_store.c" "src/certificate_wire.c"
    INCLUDE_DIRS "include" PRIV_INCLUDE_DIRS "src"
    REQUIRES wendy_ble wendy_wifi mdns esp_netif esp_wifi vfs nvs_flash wendy_net_common wendy_pki wendy_conf wendy_com wendy_net_gossip wendy_babel esp_timer esp_hw_support lwip freertos pthread espressif__cjson)

if(CONFIG_WENDY_NET_PEER AND NOT CMAKE_BUILD_EARLY_EXPANSION)
 target_compile_definitions(${COMPONENT_LIB} PUBLIC WNA_IO_BYTES=${CONFIG_WENDY_NET_IO_BYTES})
endif()
