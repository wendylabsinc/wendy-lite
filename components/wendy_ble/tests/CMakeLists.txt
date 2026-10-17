cmake_minimum_required(VERSION 3.16)
project(wendy_ble_advertising_test C)
set(CMAKE_C_STANDARD 11)
enable_testing()

# Each executable compiles the production transport with a different firmware
# configuration. Hardware calls are stubbed; advertising and GATT logic are not.
foreach(pki 0 1)
    foreach(require_mtls 0 1)
        set(target advertising_pki_${pki}_mtls_${require_mtls})
        add_executable(${target} advertising_test.c)
        target_include_directories(${target} PRIVATE stubs ../include)
        target_compile_definitions(${target} PRIVATE
            CONFIG_WENDY_BLE=1 CONFIG_WENDY_PKI=${pki}
            CONFIG_WENDY_BLE_REQUIRE_MTLS=${require_mtls}
            CONFIG_WENDY_BLE_PSM=128 CONFIG_WENDY_BLE_TASK_PRIORITY=5
            CONFIG_WENDY_BLE_TASK_CORE_AFFINITY=0)
        target_compile_options(${target} PRIVATE -UNDEBUG -Wall -Wextra -Werror
            -Wno-unused-parameter)
        add_test(NAME ${target} COMMAND ${target})
        set_tests_properties(${target} PROPERTIES TIMEOUT 5)
    endforeach()
endforeach()
