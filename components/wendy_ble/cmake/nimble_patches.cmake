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

# IDF_VER comes from git describe on the ESP-IDF checkout. A development build
# is v<major>.<minor>-dev[-<n>-g<hash>], or only <hash> when the clone has no
# tags. A release, a beta, a release candidate, a release branch and a checkout
# without git (v<major>.<minor>.<patch>) are not development builds.
function(wendy_ble_idf_is_development output idf_ver)
    if(idf_ver MATCHES "^v[0-9]+\\.[0-9]+-dev" OR idf_ver MATCHES "^[0-9a-f]+(-dirty)?$")
        set(${output} TRUE PARENT_SCOPE)
    else()
        set(${output} FALSE PARENT_SCOPE)
    endif()
endfunction()

# The opt-out exists for ESP-IDF development code that the patches do not
# support yet. A released ESP-IDF must not be adopted without them: port the
# patches first.
function(wendy_ble_check_nimble_opt_out)
    idf_build_get_property(idf_ver IDF_VER)
    wendy_ble_idf_is_development(development "${idf_ver}")
    if(NOT development)
        message(FATAL_ERROR
            "CONFIG_WENDY_BLE_PATCH_NIMBLE=n is allowed only with an ESP-IDF "
            "development build, and this is ESP-IDF ${idf_ver}. Port the NimBLE "
            "patches in components/wendy_ble/patches to this ESP-IDF before you "
            "adopt it (see patches/README.md), then remove the option.")
    endif()
    message(STATUS "wendy_ble: NimBLE host not patched "
        "(CONFIG_WENDY_BLE_PATCH_NIMBLE=n, ESP-IDF ${idf_ver})")
endfunction()

# project_include.cmake defers this to the end of the project's top-level
# CMakeLists.txt, when the bt target exists. wendy_pki's project_include.cmake
# normally defines the helpers already; load them here if it has not.
# CONFIG_WENDY_BLE_PATCH_NIMBLE=n keeps the unpatched NimBLE host, on ESP-IDF
# development builds only.
function(wendy_ble_patch_nimble)
    if(NOT CONFIG_BT_NIMBLE_ENABLED)
        return()
    endif()
    if(NOT CONFIG_WENDY_BLE_PATCH_NIMBLE)
        wendy_ble_check_nimble_opt_out()
        return()
    endif()
    if(NOT COMMAND wendy_prepare_patched_tree)
        idf_component_get_property(pki_dir wendy_pki COMPONENT_DIR)
        include("${pki_dir}/cmake/pqc_patches.cmake")
    endif()
    wendy_patch_nimble()
endfunction()
