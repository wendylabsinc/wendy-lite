# The esp-pqc patches ship with wendy_pki so that apps fetching it through the
# component manager get them too. Its helpers also patch the dependencies below.
include("${CMAKE_CURRENT_LIST_DIR}/../components/wendy_pki/cmake/pqc_patches.cmake")

function(wendy_patch_wamr)
    if(NOT TARGET idf::espressif__wasm-micro-runtime)
        return()
    endif()
    idf_component_get_property(source espressif__wasm-micro-runtime COMPONENT_DIR)
    idf_component_get_property(target espressif__wasm-micro-runtime COMPONENT_LIB)
    set(destination "${CMAKE_BINARY_DIR}/wendy_patched/wamr")
    get_filename_component(project_dir "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/.." ABSOLUTE)
    wendy_prepare_patched_tree("${source}" "${destination}"
        "${project_dir}/patches/wamr-idf6-platform.patch"
        "${project_dir}/patches/wamr-linear-mapping-replacement.patch")
    wendy_redirect_dependency_target(${target} "${source}" "${destination}")
endfunction()
