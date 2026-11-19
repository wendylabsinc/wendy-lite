# wendy_ble serves WendyCom over NimBLE L2CAP CoC, which needs fixes in the
# ESP-IDF NimBLE host (see cmake/nimble_patches.cmake). The bt target does not
# exist yet. Patch a build-local copy once the project's top-level
# CMakeLists.txt has finished, so the wendy-lite firmware and native apps that
# fetch wendy_ble through the component manager build the same NimBLE host.
include("${CMAKE_CURRENT_LIST_DIR}/cmake/nimble_patches.cmake")
cmake_language(DEFER DIRECTORY "${CMAKE_SOURCE_DIR}" CALL wendy_ble_patch_nimble)
