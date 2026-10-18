set(mesh_sources "")
if(CONFIG_WENDY_MESH_LEAF)
    list(APPEND mesh_sources "src/wendy_mesh.c" "src/wendy_mesh_protocol.c" "src/wendy_mesh_directory.c")
    if(CONFIG_WENDY_MESH_BLE)
        list(APPEND mesh_sources "src/wendy_mesh_ble.c")
    endif()
    if(CONFIG_WENDY_MESH_ESPNOW)
        list(APPEND mesh_sources "src/wendy_mesh_espnow.c" "src/wendy_mesh_datagram.c")
    endif()
endif()
# Dependency discovery runs before sdkconfig is loaded.
idf_component_register(SRCS ${mesh_sources} INCLUDE_DIRS "include"
    REQUIRES wendy_pki wendy_conf esp_timer esp_hw_support heap lwip freertos pthread wendy_ble wendy_wifi esp_wifi bt)
