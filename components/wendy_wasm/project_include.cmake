# wendy_wasm needs fixes in the WAMR runtime it pulls in (see
# cmake/wamr_patches.cmake). The WAMR target does not exist yet. Patch a
# build-local copy once the project's top-level CMakeLists.txt has finished,
# so the wendy-lite firmware and native apps that fetch wendy_wasm through the
# component manager build the same WAMR.
include("${CMAKE_CURRENT_LIST_DIR}/cmake/wamr_patches.cmake")
cmake_language(DEFER DIRECTORY "${CMAKE_SOURCE_DIR}" CALL wendy_wasm_patch_wamr)
