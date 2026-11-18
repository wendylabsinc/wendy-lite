# Keep ordinary crossed CoC disconnects from completing one channel twice.
# Compile a build-local host copy; do not modify the workstation's SDK.
# wendy_prepare_patched_tree, wendy_redirect_dependency_target and
# wendy_select_dependency_patch come from wendy_pki's cmake/pqc_patches.cmake.
function(wendy_patch_nimble)
    if(NOT CONFIG_BT_NIMBLE_ENABLED)
        return()
    endif()
    set(source "$ENV{IDF_PATH}/components/bt/host/nimble/nimble/nimble/host")
    set(destination "${CMAKE_BINARY_DIR}/wendy_patched/nimble_host")
    get_filename_component(patch_dir "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/../patches" ABSOLUTE)
    # 6.1 changed recv_ready while retaining the same credit-acceptance bug.
    # Match the actual source, not a release string or a target-specific guess.
    string(CONCAT hint
        "\nThe NimBLE patches support ESP-IDF 6.0.3 and 6.1. For another "
        "ESP-IDF, set CONFIG_WENDY_BLE_PATCH_NIMBLE=n to build the "
        "unpatched NimBLE host, without the Wendy L2CAP CoC fixes.")
    wendy_select_dependency_patch(refill_patch "${source}" HINT "${hint}"
        "${patch_dir}/idf-nimble-coc-credit-refill.patch"
        "${patch_dir}/idf-nimble-coc-credit-refill-idf61.patch")
    set(host_patches
        "${patch_dir}/idf-nimble-coc-crossed-disconnect.patch"
        "${patch_dir}/idf-nimble-coc-credit-retry.patch"
        "${refill_patch}"
        "${patch_dir}/idf-nimble-coc-backed-credit-window.patch"
        "${patch_dir}/idf-nimble-coc-initial-backed-credits.patch"
        "${patch_dir}/idf-nimble-acl-queued-retry.patch")
    wendy_prepare_patched_tree("${source}" "${destination}" ${host_patches})
    wendy_redirect_dependency_target(__idf_bt "${source}" "${destination}")
endfunction()

# project_include.cmake defers this to the end of the project's top-level
# CMakeLists.txt, when the bt target exists. wendy_pki's project_include.cmake
# normally defines the helpers already; load them here if it has not.
# CONFIG_WENDY_BLE_PATCH_NIMBLE=n (for an ESP-IDF the patches do not support)
# keeps the unpatched NimBLE host.
function(wendy_ble_patch_nimble)
    if(NOT CONFIG_WENDY_BLE_PATCH_NIMBLE)
        return()
    endif()
    if(NOT COMMAND wendy_prepare_patched_tree)
        idf_component_get_property(pki_dir wendy_pki COMPONENT_DIR)
        include("${pki_dir}/cmake/pqc_patches.cmake")
    endif()
    wendy_patch_nimble()
endfunction()
