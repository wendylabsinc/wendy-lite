# Apply reviewed fixes to build-directory copies, leaving pinned dependencies
# unchanged. Reconfiguration starts from their original files.
function(wendy_prepare_patched_tree source destination)
    find_package(Git REQUIRED)
    file(REMOVE_RECURSE "${destination}")
    file(MAKE_DIRECTORY "${destination}")
    file(COPY "${source}/" DESTINATION "${destination}" PATTERN ".git" EXCLUDE)
    # Do not let git apply discover the checkout enclosing an in-tree build.
    # It otherwise reports success while skipping paths outside that build.
    get_filename_component(patch_parent "${destination}" DIRECTORY)
    foreach(patch IN LISTS ARGN)
        set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${patch}")
        execute_process(COMMAND "${CMAKE_COMMAND}" -E env
            --unset=GIT_DIR --unset=GIT_WORK_TREE
            "GIT_CEILING_DIRECTORIES=${patch_parent}"
            "${GIT_EXECUTABLE}" apply --no-index "${patch}"
            WORKING_DIRECTORY "${destination}"
            RESULT_VARIABLE result ERROR_VARIABLE error)
        if(NOT result EQUAL 0)
            message(FATAL_ERROR "Cannot apply ${patch}: ${error}")
        endif()
    endforeach()
endfunction()

# Keep IDF's target configuration and hardware ports, but compile the patched
# source tree and use its headers consistently across all Mbed TLS libraries.
function(wendy_redirect_dependency_target target source destination)
    if(NOT TARGET ${target})
        return()
    endif()
    get_target_property(source_dir ${target} SOURCE_DIR)
    get_target_property(binary_dir ${target} BINARY_DIR)
    get_target_property(sources ${target} SOURCES)
    set(patched_sources "")
    foreach(item IN LISTS sources)
        if(NOT IS_ABSOLUTE "${item}" AND NOT item MATCHES "^\\$<")
            if(EXISTS "${source_dir}/${item}")
                set(item "${source_dir}/${item}")
            else()
                set(item "${binary_dir}/${item}")
            endif()
        endif()
        string(REPLACE "${source}/" "${destination}/" item "${item}")
        list(APPEND patched_sources "${item}")
    endforeach()
    set_property(TARGET ${target} PROPERTY SOURCES "${patched_sources}")
    foreach(property INCLUDE_DIRECTORIES INTERFACE_INCLUDE_DIRECTORIES)
        get_target_property(dirs ${target} ${property})
        if(dirs)
            string(REPLACE "${source}/" "${destination}/" dirs "${dirs}")
            set_property(TARGET ${target} PROPERTY ${property} "${dirs}")
        endif()
    endforeach()
endfunction()

# The liboqs tree defaults to its place in an esp-pqc checkout. Pass it when
# the component manager installs Mbed TLS outside esp-pqc.
function(wendy_patch_mbedtls source)
    get_filename_component(source "${source}" ABSOLUTE)
    set(destination "${CMAKE_BINARY_DIR}/wendy_patched/mbedtls")
    get_filename_component(component_dir "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/.." ABSOLUTE)
    wendy_prepare_patched_tree("${source}" "${destination}"
        "${component_dir}/patches/esp-pqc-mbedtls4-private-headers.patch"
        "${component_dir}/patches/esp-pqc-mbedtls-tls13-certificate-fragmentation.patch"
        "${component_dir}/patches/esp-pqc-mbedtls-mldsa87-ca.patch"
        "${component_dir}/patches/esp-pqc-mbedtls-lazy-handshake-buffer.patch"
        "${component_dir}/patches/esp-pqc-mbedtls-asymmetric-input-buffer.patch"
        "${component_dir}/patches/esp-pqc-mbedtls-lazy-pqc-public-key.patch"
        "${component_dir}/patches/esp-pqc-mbedtls-record-sized-reassembly.patch"
        "${component_dir}/patches/esp-pqc-mbedtls-reuse-peer-trust-anchor.patch"
        "${component_dir}/patches/esp-pqc-mbedtls-input-reserve.patch"
        "${component_dir}/patches/esp-pqc-mbedtls-reuse-own-issuers.patch"
        "${component_dir}/patches/esp-pqc-mbedtls-release-issuer-candidates.patch"
        "${component_dir}/patches/esp-pqc-mbedtls-demand-application-record.patch"
        "${component_dir}/patches/esp-pqc-mbedtls-consume-pem-der.patch"
        "${component_dir}/patches/esp-pqc-mbedtls-borrow-verified-peer-issuers.patch"
        "${component_dir}/patches/esp-pqc-mbedtls-stream-verified-own-chain.patch"
        "${component_dir}/patches/esp-pqc-mbedtls-defer-peer-leaf-copy.patch"
        "${component_dir}/patches/esp-pqc-mbedtls-small-initial-stream-record.patch"
        "${component_dir}/patches/esp-pqc-mbedtls-borrow-certificate-pqc-keys.patch"
        "${component_dir}/patches/esp-pqc-mbedtls-direct-small-input-setup.patch"
        "${component_dir}/patches/esp-pqc-mbedtls-preserve-pending-output.patch"
        "${component_dir}/patches/esp-pqc-mbedtls-adopt-input-reservation.patch"
        "${component_dir}/patches/esp-pqc-mbedtls-recycle-input-buffer.patch"
        "${component_dir}/patches/esp-pqc-mbedtls-defer-handshake-input-shrink.patch"
        "${component_dir}/patches/esp-pqc-mbedtls-psa-global-key-tables.patch"
        "${component_dir}/patches/esp-pqc-mbedtls-mldsa65-private-key.patch"
        "${component_dir}/patches/esp-pqc-mbedtls-mldsa65-certificate-verify.patch")
    foreach(target __idf_mbedtls mbedtls mbedx509 tfpsacrypto builtin extras platform utilities everest p256-m)
        wendy_redirect_dependency_target(${target} "${source}" "${destination}")
        if(ESP_PLATFORM)
            # Newer IDF releases export their own vendor headers in addition to
            # the override's library targets. Those headers have no PQC key
            # fields and must not precede the patched library's headers.
            wendy_redirect_dependency_target(${target}
                "$ENV{IDF_PATH}/components/mbedtls/mbedtls" "${destination}")
        endif()
        if(TARGET ${target} AND (NOT ESP_PLATFORM OR CONFIG_MBEDTLS_SSL_TLS1_3_SIG_MLDSA65))
            # The inline key buffer layout must match in every consumer.
            target_compile_definitions(${target} PUBLIC MBEDTLS_X509_MLDSA87=)
        endif()
        if(TARGET ${target} AND (CONFIG_WENDY_PKI_MLDSA65_SIGNING OR WENDY_PKI_MLDSA65_SIGNING))
            # Layout and opt-in private-key backend must match every consumer.
            target_compile_definitions(${target} PUBLIC MBEDTLS_MLDSA65_PRIVATE_KEY=)
        endif()
    endforeach()
    if(TARGET ml_dsa_87_ref)
        if(ARGC GREATER 1)
            set(oqs_source "${ARGV1}")
        else()
            set(oqs_source "${source}/../../liboqs/liboqs")
        endif()
        get_filename_component(oqs_source "${oqs_source}" ABSOLUTE)
        wendy_patch_liboqs("${oqs_source}")
    endif()
endfunction()

function(wendy_patch_liboqs source)
    set(destination "${CMAKE_BINARY_DIR}/wendy_patched/liboqs")
    get_filename_component(component_dir "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/.." ABSOLUTE)
    wendy_prepare_patched_tree("${source}" "${destination}"
        "${component_dir}/patches/esp-pqc-liboqs-mldsa87.patch")
    wendy_redirect_dependency_target(ml_dsa_87_ref "${source}" "${destination}")
    if(ESP_PLATFORM)
        target_include_directories(ml_dsa_87_ref PRIVATE "${source}/../ports")
        target_compile_definitions(ml_dsa_87_ref PRIVATE
            MLD_CONFIG_FIPS202_CUSTOM_HEADER="esp_mld_fips202_glue.h"
            MLD_CONFIG_SERIAL_FIPS202_ONLY MLD_POLY_UNIFORM_NBLOCKS=5
            LIBOQS_MLD_VERIFY_ONLY)
    endif()
endfunction()

# project_include.cmake defers this to the end of the project's top-level
# CMakeLists.txt, so the firmware and apps that fetch wendy_pki through the
# component manager build the same patched Mbed TLS.
function(wendy_pki_patch_bundled_mbedtls)
    if(NOT CONFIG_MBEDTLS_USE_BUNDLED_PQC)
        return()
    endif()
    if(CONFIG_MBEDTLS_DYNAMIC_BUFFER)
        message(FATAL_ERROR
            "The bundled esp-pqc Mbed TLS backend requires fixed receive buffers. "
            "ESP-IDF dynamic buffers do not satisfy its handshake reassembly bounds. "
            "Disable CONFIG_MBEDTLS_DYNAMIC_BUFFER or configure a fresh sdkconfig.")
    endif()
    idf_component_get_property(mbedtls_dir mbedtls COMPONENT_DIR)
    idf_component_get_property(pqc_dir esp-pqc COMPONENT_DIR)
    wendy_patch_mbedtls("${mbedtls_dir}/mbedtls" "${pqc_dir}/components/liboqs/liboqs")
endfunction()
