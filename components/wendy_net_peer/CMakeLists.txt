set(native_driver_sources)
if(CONFIG_WENDY_NET_PEER)
 list(APPEND native_driver_sources "src/app.c" "src/native_agent.c" "src/agent_bridge.c" "src/agent_pipe.c" "src/peer.c" "src/actor.c" "src/actor_driver.c" "src/selection.c" "src/ble_protocol.c" "src/carrier.c" "src/packet_queue.c" "src/netif_effect.c" "src/mdns_effect.c" "src/time_control.c" "src/nan_protocol.c" "src/settings.c")
else()
 list(APPEND native_driver_sources "src/native_staging.c")
endif()
idf_component_register(SRCS ${native_driver_sources} "src/operator.c" "src/router.c" "src/control.c" "src/router_session.c" "src/topology_record.c" "src/crypto_job.c" "src/certificate_worker.c" "src/certificate_read.c" "src/catalog_node.c" "src/manifest_catalog.c" "src/catalog_guest.c" "src/service_store.c"  "src/protocol.c" "src/binary.c" "src/packet.c" "src/directory.c" "src/manifest_service.c" "src/service_protocol.c" "src/guest_json.c" "src/certificate_fetch.c" "src/certificate_store.c" "src/certificate_wire.c"
    INCLUDE_DIRS "include" PRIV_INCLUDE_DIRS "src"
    REQUIRES wendy_ble wendy_wifi mdns esp_netif esp_wifi vfs nvs_flash wendy_net_common wendy_pki wendy_conf wendy_com wendy_net_gossip wendy_babel esp_timer esp_hw_support lwip freertos pthread espressif__cjson)

if(CONFIG_WENDY_NET_PEER AND NOT CMAKE_BUILD_EARLY_EXPANSION)
 target_compile_definitions(${COMPONENT_LIB} PUBLIC WNA_IO_BYTES=${CONFIG_WENDY_NET_IO_BYTES})
endif()

# Guest networking is selected by the product/WASM entry point. Add its public
# headers/link closure only when present, keeping native-OFF builds independent
# of the optional WASM runtime during IDF's early component discovery.
if(CONFIG_WENDY_NET AND NOT CMAKE_BUILD_EARLY_EXPANSION)
 idf_component_optional_requires(PRIVATE wendy_net)
endif()
