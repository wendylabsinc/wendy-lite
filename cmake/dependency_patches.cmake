# The esp-pqc patches ship with wendy_pki so that apps fetching it through the
# component manager get them too. Its helpers also patch the dependencies below.
include("${CMAKE_CURRENT_LIST_DIR}/../components/wendy_pki/cmake/pqc_patches.cmake")

# Select a supported dependency source layout without changing its source.
function(wendy_select_dependency_patch output source)
    find_package(Git REQUIRED)
    get_filename_component(patch_parent "${source}" DIRECTORY)
    foreach(patch IN LISTS ARGN)
        set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${patch}")
        execute_process(COMMAND "${CMAKE_COMMAND}" -E env
            --unset=GIT_DIR --unset=GIT_WORK_TREE
            "GIT_CEILING_DIRECTORIES=${patch_parent}"
            "${GIT_EXECUTABLE}" apply --check --no-index "${patch}"
            WORKING_DIRECTORY "${source}"
            RESULT_VARIABLE result ERROR_VARIABLE error)
        if(result EQUAL 0)
            set(${output} "${patch}" PARENT_SCOPE)
            return()
        endif()
    endforeach()
    message(FATAL_ERROR "No supported dependency patch matches ${source}: ${error}")
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

# Keep ordinary crossed CoC disconnects from completing one channel twice.
# Compile a build-local host copy; do not modify the workstation's SDK.
function(wendy_patch_nimble)
    if(NOT CONFIG_BT_NIMBLE_ENABLED)
        return()
    endif()
    set(source "$ENV{IDF_PATH}/components/bt/host/nimble/nimble/nimble/host")
    set(destination "${CMAKE_BINARY_DIR}/wendy_patched/nimble_host")
    get_filename_component(project_dir "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/.." ABSOLUTE)
    # 6.1 changed recv_ready while retaining the same credit-acceptance bug.
    # Match the actual source, not a release string or a target-specific guess.
    wendy_select_dependency_patch(refill_patch "${source}"
        "${project_dir}/patches/idf-nimble-coc-credit-refill.patch"
        "${project_dir}/patches/idf-nimble-coc-credit-refill-idf61.patch")
    set(host_patches
        "${project_dir}/patches/idf-nimble-coc-crossed-disconnect.patch"
        "${project_dir}/patches/idf-nimble-coc-credit-retry.patch"
        "${refill_patch}"
        "${project_dir}/patches/idf-nimble-coc-backed-credit-window.patch"
        "${project_dir}/patches/idf-nimble-acl-queued-retry.patch")
    wendy_prepare_patched_tree("${source}" "${destination}" ${host_patches})
    wendy_redirect_dependency_target(__idf_bt "${source}" "${destination}")
endfunction()
