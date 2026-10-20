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

function(wendy_patch_mbedtls source)
    get_filename_component(source "${source}" ABSOLUTE)
    set(destination "${CMAKE_BINARY_DIR}/wendy_patched/mbedtls")
    get_filename_component(project_dir "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/.." ABSOLUTE)
    wendy_prepare_patched_tree("${source}" "${destination}"
        "${project_dir}/patches/esp-pqc-mbedtls4-private-headers.patch"
        "${project_dir}/patches/esp-pqc-mbedtls-tls13-certificate-fragmentation.patch"
        "${project_dir}/patches/esp-pqc-mbedtls-mldsa87-ca.patch")
    foreach(target __idf_mbedtls mbedtls mbedx509 tfpsacrypto builtin extras platform utilities everest p256-m)
        wendy_redirect_dependency_target(${target} "${source}" "${destination}")
        if(TARGET ${target} AND (NOT ESP_PLATFORM OR CONFIG_MBEDTLS_SSL_TLS1_3_SIG_MLDSA65))
            # The inline key buffer layout must match in every consumer.
            target_compile_definitions(${target} PUBLIC MBEDTLS_X509_MLDSA87=)
        endif()
    endforeach()
    if(TARGET ml_dsa_87_ref)
        get_filename_component(oqs_source "${source}/../../liboqs/liboqs" ABSOLUTE)
        wendy_patch_liboqs("${oqs_source}")
    endif()
endfunction()

function(wendy_patch_liboqs source)
    set(destination "${CMAKE_BINARY_DIR}/wendy_patched/liboqs")
    get_filename_component(project_dir "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/.." ABSOLUTE)
    wendy_prepare_patched_tree("${source}" "${destination}"
        "${project_dir}/patches/esp-pqc-liboqs-mldsa87.patch")
    wendy_redirect_dependency_target(ml_dsa_87_ref "${source}" "${destination}")
    if(ESP_PLATFORM)
        target_include_directories(ml_dsa_87_ref PRIVATE "${source}/../ports")
        target_compile_definitions(ml_dsa_87_ref PRIVATE
            MLD_CONFIG_FIPS202_CUSTOM_HEADER="esp_mld_fips202_glue.h"
            MLD_CONFIG_SERIAL_FIPS202_ONLY MLD_POLY_UNIFORM_NBLOCKS=5
            LIBOQS_MLD_VERIFY_ONLY)
    endif()
endfunction()

function(wendy_patch_wamr)
    if(NOT TARGET idf::espressif__wasm-micro-runtime)
        return()
    endif()
    idf_component_get_property(source espressif__wasm-micro-runtime COMPONENT_DIR)
    idf_component_get_property(target espressif__wasm-micro-runtime COMPONENT_LIB)
    set(destination "${CMAKE_BINARY_DIR}/wendy_patched/wamr")
    get_filename_component(project_dir "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/.." ABSOLUTE)
    wendy_prepare_patched_tree("${source}" "${destination}"
        "${project_dir}/patches/wamr-idf6-platform.patch")
    wendy_redirect_dependency_target(${target} "${source}" "${destination}")
endfunction()
