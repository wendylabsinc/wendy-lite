# Patch espressif/wasm-micro-runtime for ESP-IDF 6 and linear-memory
# replacement (see patches/README.md at the wendy-lite root). Compile a
# build-local copy; the downloaded component stays unchanged.
# wendy_prepare_patched_tree and wendy_redirect_dependency_target come from
# wendy_pki's cmake/pqc_patches.cmake.
function(wendy_patch_wamr)
    if(NOT TARGET idf::espressif__wasm-micro-runtime)
        return()
    endif()
    idf_component_get_property(source espressif__wasm-micro-runtime COMPONENT_DIR)
    idf_component_get_property(target espressif__wasm-micro-runtime COMPONENT_LIB)
    set(destination "${CMAKE_BINARY_DIR}/wendy_patched/wamr")
    get_filename_component(patch_dir "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/../patches" ABSOLUTE)
    wendy_prepare_patched_tree("${source}" "${destination}"
        "${patch_dir}/wamr-idf6-platform.patch"
        "${patch_dir}/wamr-linear-mapping-replacement.patch")
    wendy_redirect_dependency_target(${target} "${source}" "${destination}")
endfunction()

# project_include.cmake defers this to the end of the project's top-level
# CMakeLists.txt, when the WAMR target exists. wendy_pki's project_include.cmake
# normally defines the helpers already; load them here if it has not.
function(wendy_wasm_patch_wamr)
    if(NOT TARGET idf::espressif__wasm-micro-runtime)
        return()
    endif()
    if(NOT COMMAND wendy_prepare_patched_tree)
        idf_component_get_property(pki_dir wendy_pki COMPONENT_DIR)
        include("${pki_dir}/cmake/pqc_patches.cmake")
    endif()
    wendy_patch_wamr()
endfunction()
