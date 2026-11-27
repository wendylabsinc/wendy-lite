# Apply both Hosted patches to the same build-local source tree.
function(wendy_patch_hosted)
    if(NOT CONFIG_IDF_TARGET_ESP32P4 OR NOT CONFIG_WENDY_WIFI_ENABLED OR
       NOT TARGET idf::espressif__esp_hosted)
        return()
    endif()

    set(patches "")
    if(CONFIG_ESP_HOSTED_CP_TARGET_ESP32C6)
        list(APPEND patches "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/patches/esp-hosted-companion-version.patch")
    endif()
    if(CONFIG_WENDY_NET_PEER AND CONFIG_ESP_HOSTED_ENABLE_PEER_DATA_TRANSFER AND
       CONFIG_ESP_HOSTED_SDIO_HOST_INTERFACE)
        idf_component_get_property(net_peer wendy_net_peer COMPONENT_DIR)
        list(APPEND patches "${net_peer}/patches/esp-hosted-sdio.patch")
    endif()
    if(NOT patches)
        return()
    endif()

    idf_component_get_property(pki wendy_pki COMPONENT_DIR)
    include("${pki}/cmake/pqc_patches.cmake")
    idf_component_get_property(source espressif__esp_hosted COMPONENT_DIR)
    idf_component_get_property(target espressif__esp_hosted COMPONENT_LIB)
    set(destination "${CMAKE_BINARY_DIR}/wendy_patched/esp_hosted")
    wendy_prepare_patched_tree("${source}" "${destination}" ${patches})
    wendy_redirect_dependency_target(${target} "${source}" "${destination}")
    if(net_peer)
        target_include_directories(${target} PRIVATE "${net_peer}/include")
    endif()
endfunction()

cmake_language(DEFER DIRECTORY "${CMAKE_SOURCE_DIR}" CALL wendy_patch_hosted)
