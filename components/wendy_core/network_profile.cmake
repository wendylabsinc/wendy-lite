# Check resolved configuration, not defaults files. This catches stale sdkconfig
# values and unsupported overlay combinations before compiling firmware.
function(wendy_check_network_profile)
    if(NOT CONFIG_WENDY_WIFI_TEST_PSRAM_THROUGHPUT)
        return()
    endif()
    if(NOT CONFIG_IDF_TARGET STREQUAL "esp32c5" AND NOT CONFIG_IDF_TARGET STREQUAL "esp32s3")
        message(FATAL_ERROR "PSRAM throughput profile supports only ESP32-C5 and ESP32-S3")
    endif()
    foreach(flag WENDY_WIFI_ENABLED SPIRAM SPIRAM_BOOT_INIT SPIRAM_USE_MALLOC
                 SPIRAM_TRY_ALLOCATE_WIFI_LWIP ESP_WIFI_STATIC_TX_BUFFER)
        if(NOT CONFIG_${flag})
            message(FATAL_ERROR "PSRAM throughput profile requires CONFIG_${flag}=y")
        endif()
    endforeach()
    if(CONFIG_SPIRAM_IGNORE_NOTFOUND OR CONFIG_WENDY_NET_CONSTRAINED_PROFILE)
        message(FATAL_ERROR "PSRAM throughput profile requires PSRAM at boot and a non-constrained board")
    endif()
    if(NOT DEFINED CONFIG_SPIRAM_MALLOC_RESERVE_INTERNAL OR
       CONFIG_SPIRAM_MALLOC_RESERVE_INTERNAL LESS 32768)
        message(FATAL_ERROR "PSRAM throughput profile requires at least 32768 bytes of internal reserve")
    endif()
    if(NOT DEFINED CONFIG_SPIRAM_MALLOC_ALWAYSINTERNAL OR
       CONFIG_SPIRAM_MALLOC_ALWAYSINTERNAL GREATER 1024)
        message(FATAL_ERROR "PSRAM throughput profile requires an internal allocation threshold at most 1024")
    endif()
    if(NOT DEFINED CONFIG_LWIP_MAX_SOCKETS OR CONFIG_LWIP_MAX_SOCKETS LESS 1 OR
       CONFIG_LWIP_MAX_SOCKETS GREATER 24)
        message(FATAL_ERROR "PSRAM throughput profile supports 1 to 24 lwIP sockets")
    endif()
    foreach(setting
            "LWIP_TCP_MSS;1440"
            "LWIP_TCP_SND_BUF_DEFAULT;32768" "LWIP_TCP_WND_DEFAULT;32768"
            "LWIP_TCP_RECVMBOX_SIZE;32" "LWIP_TCPIP_RECVMBOX_SIZE;64"
            "ESP_WIFI_STATIC_RX_BUFFER_NUM;8" "ESP_WIFI_DYNAMIC_RX_BUFFER_NUM;32"
            "ESP_WIFI_STATIC_TX_BUFFER_NUM;8" "ESP_WIFI_CACHE_TX_BUFFER_NUM;32"
            "ESP_WIFI_RX_BA_WIN;6")
        list(GET setting 0 key)
        list(GET setting 1 value)
        if(NOT DEFINED CONFIG_${key} OR NOT "${CONFIG_${key}}" STREQUAL "${value}")
            message(FATAL_ERROR "PSRAM throughput profile requires CONFIG_${key}=${value}; use a fresh sdkconfig or update its resolved value")
        endif()
    endforeach()
    message(STATUS "Wendy PSRAM throughput qualification profile: TCP 32768/32768, RX mailbox 32, Wi-Fi RX/TX 8/8, internal reserve ${CONFIG_SPIRAM_MALLOC_RESERVE_INTERNAL}")
endfunction()

# Standalone validation of an ESP-IDF-generated config/sdkconfig.cmake.
if(DEFINED WENDY_NETWORK_CONFIG)
    include("${WENDY_NETWORK_CONFIG}")
    wendy_check_network_profile()
endif()
