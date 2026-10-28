cmake_minimum_required(VERSION 3.20)
project(wendy_nimble_sdk_tests NONE)
enable_testing()
find_package(Python3 REQUIRED COMPONENTS Interpreter)
set(WENDY_TEST_IDF_PATH "$ENV{IDF_PATH}" CACHE PATH "Unmodified supported ESP-IDF checkout")
if(NOT EXISTS "${WENDY_TEST_IDF_PATH}/components/bt/host/nimble/nimble/nimble/host/src/ble_l2cap_coc.c")
    message(FATAL_ERROR "Set WENDY_TEST_IDF_PATH or IDF_PATH to a supported ESP-IDF checkout")
endif()
option(WENDY_TEST_SANITIZE "Run portable SDK fixtures with ASan and UBSan" OFF)
set(sanitizer_arg)
if(WENDY_TEST_SANITIZE)
    set(sanitizer_arg --sanitize)
endif()
foreach(fixture credit_retry acl_retry disconnect)
    add_test(NAME nimble_${fixture} COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_LIST_DIR}/nimble_${fixture}_test.py"
        --idf "${WENDY_TEST_IDF_PATH}" ${sanitizer_arg})
    set_tests_properties(nimble_${fixture} PROPERTIES TIMEOUT 120)
endforeach()
add_test(NAME nimble_build_local_registration COMMAND "${CMAKE_COMMAND}"
    -S "${CMAKE_CURRENT_LIST_DIR}/nimble_registration"
    -B "${CMAKE_CURRENT_BINARY_DIR}/registration"
    "-DWENDY_TEST_IDF_PATH=${WENDY_TEST_IDF_PATH}")
add_test(NAME dependency_patches_in_checkout COMMAND "${CMAKE_COMMAND}" -P
    "${CMAKE_CURRENT_LIST_DIR}/dependency_patches_test.cmake")
# Optional whole-translation-unit check, using an existing firmware's generated
# config and toolchain flags without reconfiguring or writing into that build.
set(WENDY_TEST_COMPILE_COMMANDS "" CACHE FILEPATH "Existing IDF firmware compile_commands.json")
if(WENDY_TEST_COMPILE_COMMANDS)
    add_test(NAME nimble_whole_sdk_compile COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_LIST_DIR}/nimble_sdk_compile_test.py"
        --idf "${WENDY_TEST_IDF_PATH}" --compile-commands "${WENDY_TEST_COMPILE_COMMANDS}")
    set_tests_properties(nimble_whole_sdk_compile PROPERTIES TIMEOUT 180)
endif()
