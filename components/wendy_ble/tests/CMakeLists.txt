cmake_minimum_required(VERSION 3.16)
project(wendy_ble_advertising_test C)
set(CMAKE_C_STANDARD 11)
enable_testing()
include_directories(../../wendy_net_common/include)

add_executable(mesh_report_lifetime_success_test mesh_report_lifetime_success_test.c)
target_include_directories(mesh_report_lifetime_success_test PRIVATE ../src)
target_compile_options(mesh_report_lifetime_success_test PRIVATE -UNDEBUG -Wall -Wextra -Werror)
add_test(NAME mesh_report_lifetime_success COMMAND mesh_report_lifetime_success_test)
add_executable(mesh_gap_effect_success_test mesh_gap_effect_success_test.c)
target_include_directories(mesh_gap_effect_success_test PRIVATE ../src)
target_compile_options(mesh_gap_effect_success_test PRIVATE -UNDEBUG -Wall -Wextra -Werror)
add_test(NAME mesh_gap_effect_success COMMAND mesh_gap_effect_success_test)

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

add_executable(constrained_management_advertising_success_test
    constrained_management_advertising_success_test.c)
target_include_directories(constrained_management_advertising_success_test PRIVATE stubs ../include)
target_compile_definitions(constrained_management_advertising_success_test PRIVATE
    CONFIG_WENDY_BLE=1 CONFIG_WENDY_PKI=1 CONFIG_WENDY_BLE_REQUIRE_MTLS=1
    CONFIG_WENDY_BLE_PSM=128 CONFIG_WENDY_BLE_TASK_PRIORITY=5
    CONFIG_WENDY_BLE_TASK_CORE_AFFINITY=0 CONFIG_WENDY_NET_BLE=1
    CONFIG_WENDY_NET_CONSTRAINED_PROFILE=1)
target_compile_options(constrained_management_advertising_success_test PRIVATE
    -UNDEBUG -Wall -Wextra -Werror -Wno-unused-parameter)
add_test(NAME constrained_management_advertising_success
    COMMAND constrained_management_advertising_success_test)

find_package(Threads REQUIRED)
add_executable(handshake_dispatch_success_test handshake_dispatch_success_test.c
    ../../wendy_pki/src/wendy_pki_work.c ../../wendy_net_common/src/memory.c ../../wendy_net_common/src/runtime_memory.c)
target_include_directories(handshake_dispatch_success_test PRIVATE stubs ../include ../../wendy_pki/include ../../wendy_pki/src)
target_compile_definitions(handshake_dispatch_success_test PRIVATE CONFIG_WENDY_BLE=1 CONFIG_WENDY_PKI=1 CONFIG_WENDY_BLE_REQUIRE_MTLS=1 CONFIG_WENDY_NET_PEER=1 WENDY_BLE_IO_DISPATCH_TEST=1 CONFIG_WENDY_BLE_PSM=128 CONFIG_WENDY_BLE_TASK_PRIORITY=5 CONFIG_WENDY_BLE_TASK_CORE_AFFINITY=0)
target_link_libraries(handshake_dispatch_success_test PRIVATE Threads::Threads)
target_compile_options(handshake_dispatch_success_test PRIVATE -UNDEBUG -Wall -Wextra -Werror -Wno-unused-parameter)
add_test(NAME physical_ble_io_dispatch COMMAND handshake_dispatch_success_test)

add_executable(management_advertising_retry_success_test management_advertising_retry_success_test.c)
target_include_directories(management_advertising_retry_success_test PRIVATE stubs ../include)
target_compile_definitions(management_advertising_retry_success_test PRIVATE CONFIG_WENDY_BLE=1 CONFIG_WENDY_PKI=1 CONFIG_WENDY_BLE_REQUIRE_MTLS=1 CONFIG_WENDY_NET_BLE=1 CONFIG_WENDY_NET_CONSTRAINED_PROFILE=0 CONFIG_WENDY_BLE_PSM=128 CONFIG_WENDY_BLE_TASK_PRIORITY=5 CONFIG_WENDY_BLE_TASK_CORE_AFFINITY=0)
target_compile_options(management_advertising_retry_success_test PRIVATE -UNDEBUG -Wall -Wextra -Werror -Wno-unused-parameter)
add_test(NAME management_advertising_retry COMMAND management_advertising_retry_success_test)

add_executable(incoming_gap_lifetime_success_test incoming_gap_lifetime_success_test.c)
target_include_directories(incoming_gap_lifetime_success_test PRIVATE stubs ../include)
target_compile_definitions(incoming_gap_lifetime_success_test PRIVATE CONFIG_WENDY_BLE=1 CONFIG_WENDY_PKI=1 CONFIG_WENDY_BLE_REQUIRE_MTLS=1 CONFIG_WENDY_NET_BLE=1 CONFIG_WENDY_NET_CONSTRAINED_PROFILE=0 CONFIG_WENDY_BLE_PSM=128 CONFIG_WENDY_BLE_TASK_PRIORITY=5 CONFIG_WENDY_BLE_TASK_CORE_AFFINITY=0)
target_compile_options(incoming_gap_lifetime_success_test PRIVATE -UNDEBUG -Wall -Wextra -Werror -Wno-unused-parameter)
add_test(NAME incoming_gap_lifetime COMMAND incoming_gap_lifetime_success_test)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
add_test(NAME mesh_connection_claim COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/mesh_connection_claim_success_test.py)
add_test(NAME physical_rx_rearm COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/physical_rx_rearm_success_test.py)

add_test(NAME mesh_output_drain COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/mesh_output_drain_success_test.py)
