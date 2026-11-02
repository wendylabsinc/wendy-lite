if(CONFIG_WENDY_PKI)
    foreach(kind DEVICE TSA HTTPS)
        string(TOLOWER "${kind}" lower_kind)
        set(root_bundle "")
        if(NOT "${CONFIG_WENDY_PKI_${kind}_ROOTS}" STREQUAL "")
            get_filename_component(root_bundle "${CONFIG_WENDY_PKI_${kind}_ROOTS}" ABSOLUTE BASE_DIR "${CMAKE_SOURCE_DIR}")
            if(NOT EXISTS "${root_bundle}")
                message(FATAL_ERROR "WENDY_PKI_${kind}_ROOTS must name a pinned certificate bundle")
            endif()
            set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${root_bundle}")
        endif()
        execute_process(COMMAND "${PYTHON}" "${CMAKE_CURRENT_SOURCE_DIR}/tools/import_roots.py"
            "${root_bundle}" "${CMAKE_CURRENT_BINARY_DIR}/${lower_kind}_roots.der"
            RESULT_VARIABLE import_result)
        if(NOT import_result EQUAL 0)
            message(FATAL_ERROR "Could not import ${kind} roots as DER")
        endif()
    endforeach()
    set(pki_backend_sources "src/wendy_pki_verify.c" "src/wendy_pki_tls.c" "src/wendy_pki_public_index.c" "src/wendy_pki_public_read.c" "src/wendy_pki_tls_input.c" "src/wendy_pki_mesh_crypto.c" "src/wendy_pki_der_cache.c" "src/wendy_pki_work.c")
    idf_component_register(SRCS "src/wendy_operator_auth.c" "src/wendy_lite_authority.c" "src/wendy_pki_crypto.c" "src/wendy_lite_grant.c" "src/wendy_pki.c" ${pki_backend_sources}
        INCLUDE_DIRS "include" REQUIRES wendy_net_common mbedtls esp-pqc wendy_conf nvs_flash esp_timer esp_hw_support esp_system http_parser lwip pthread)
    foreach(kind device tsa https)
        target_add_binary_data(${COMPONENT_LIB} "${CMAKE_CURRENT_BINARY_DIR}/${kind}_roots.der" BINARY RENAME_TO "wendy_pki_${kind}_roots")
    endforeach()
else()
    idf_component_register(SRCS "src/wendy_operator_auth.c" "src/wendy_pki_crypto.c" "src/wendy_pki_stub.c" INCLUDE_DIRS "include" REQUIRES wendy_net_common mbedtls esp-pqc wendy_conf nvs_flash esp_timer esp_hw_support esp_system http_parser lwip pthread)
endif()

# The pinned ESP liboqs exposes custom heap-temporary macros. Route native
# ML-DSA matrices/vectors through the same initiating-owner ledger as TLS, rather
# than leaving their large raw malloc temporaries outside the budget. This adds
# no source patch and preserves its existing reduced-RAM/algorithm profiles.
if(CONFIG_LIBOQS_MLD_HEAP_TEMPORARIES AND NOT CMAKE_BUILD_EARLY_EXPANSION)
    if(CONFIG_MBEDTLS_SSL_TLS1_3_SIG_MLDSA65 AND NOT TARGET ml_dsa_65_ref)
        message(FATAL_ERROR "Wendy PKI requires the scoped ML-DSA reference allocator target")
    endif()
    foreach(level 44 65 87)
        if(TARGET ml_dsa_${level}_ref)
            message(STATUS "Wendy PKI: scoped ML-DSA ${level} heap temporaries")
            target_compile_definitions(ml_dsa_${level}_ref PRIVATE
                LIBOQS_MLD_EXTERNAL_ALLOC MLD_CONFIG_CUSTOM_ALLOC_FREE MLD_CONFIG_REDUCE_RAM)
            target_compile_options(ml_dsa_${level}_ref PRIVATE
                "-include${CMAKE_CURRENT_SOURCE_DIR}/src/wendy_pki_mld_alloc.h")
        endif()
    endforeach()
endif()
