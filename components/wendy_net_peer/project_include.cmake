# Patch the Hosted SDIO source in a build-local copy. Native apps that consume
# Wendy Net run the same hook when CMake has created the Hosted target.
function(wendy_espnow_patch_hosted_sdio)
    if(NOT CONFIG_IDF_TARGET_ESP32P4 OR NOT CONFIG_WENDY_NET_PEER OR NOT CONFIG_WENDY_WIFI_ENABLED OR
       NOT CONFIG_ESP_HOSTED_ENABLE_PEER_DATA_TRANSFER OR NOT CONFIG_ESP_HOSTED_SDIO_HOST_INTERFACE OR
       NOT TARGET idf::espressif__esp_hosted)
        return()
    endif()
    idf_component_get_property(pki wendy_pki COMPONENT_DIR)
    include("${pki}/cmake/pqc_patches.cmake")
    idf_component_get_property(source espressif__esp_hosted COMPONENT_DIR)
    idf_component_get_property(target espressif__esp_hosted COMPONENT_LIB)
    set(destination "${CMAKE_BINARY_DIR}/wendy_patched/esp_hosted")
    set(component_dir "${CMAKE_CURRENT_FUNCTION_LIST_DIR}")
    wendy_prepare_patched_tree("${source}" "${destination}"
        "${component_dir}/patches/esp-hosted-sdio.patch")
    wendy_redirect_dependency_target(${target} "${source}" "${destination}")
    target_include_directories(${target} PRIVATE "${component_dir}/include")
endfunction()

cmake_language(DEFER DIRECTORY "${CMAKE_SOURCE_DIR}" CALL wendy_espnow_patch_hosted_sdio)
