cmake_minimum_required(VERSION 3.20)
include("${CMAKE_CURRENT_LIST_DIR}/../dependency_patches.cmake")
find_package(Git REQUIRED)

# Reproduce an in-checkout build. Without isolation, git apply reports success
# while skipping every file because the build directory is below the repo root.
set(root "${CMAKE_CURRENT_BINARY_DIR}/dependency-patches-test")
file(REMOVE_RECURSE "${root}")
file(MAKE_DIRECTORY "${root}/source" "${root}/checkout/build")
execute_process(COMMAND "${GIT_EXECUTABLE}" init -q "${root}/checkout"
    COMMAND_ERROR_IS_FATAL ANY)
file(WRITE "${root}/source/value.txt" "original\n")
file(WRITE "${root}/fix.patch"
    "diff --git a/value.txt b/value.txt\n--- a/value.txt\n+++ b/value.txt\n@@ -1 +1 @@\n-original\n+patched\n")
foreach(pass RANGE 1 2)
    if(pass EQUAL 2)
        # IDEs and Git hooks can pass an explicit enclosing repository too.
        set(ENV{GIT_DIR} "${root}/checkout/.git")
        set(ENV{GIT_WORK_TREE} "${root}/checkout")
    endif()
    wendy_prepare_patched_tree("${root}/source" "${root}/checkout/build/patched"
        "${root}/fix.patch")
    file(READ "${root}/checkout/build/patched/value.txt" actual)
    if(NOT actual STREQUAL "patched\n")
        message(FATAL_ERROR "Patch was skipped on pass ${pass}: ${actual}")
    endif()
    file(READ "${root}/source/value.txt" original)
    if(NOT original STREQUAL "original\n")
        message(FATAL_ERROR "Patching changed the dependency source")
    endif()
endforeach()
file(REMOVE_RECURSE "${root}")
