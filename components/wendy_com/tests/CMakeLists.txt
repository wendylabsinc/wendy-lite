cmake_minimum_required(VERSION 3.16)
project(wendy_com_sensor_test C)
set(CMAKE_C_STANDARD 11)
enable_testing()
find_package(Threads REQUIRED)
add_executable(service_description_success_test service_description_success_test.c ../src/wendy_com_service.c)
target_include_directories(service_description_success_test PRIVATE ../include
    ../../wendy_conf/include ../../nanopb ../../wendy_pki/tests/stubs)
target_compile_options(service_description_success_test PRIVATE -UNDEBUG -Wall -Wextra -Werror)
add_test(NAME service_description_success COMMAND service_description_success_test)

add_executable(sensor_stream_test sensor_stream_test.c ../src/wendy_com_sensor.c
    ../../wendy_core/src/wendy_core_sensor.c ../src/sensorlink.pb.c
    ../../nanopb/pb_common.c ../../nanopb/pb_encode.c ../../nanopb/pb_decode.c)
target_include_directories(sensor_stream_test PRIVATE sensor_stubs ../include
    ../../wendy_core/include ../../nanopb)
target_compile_options(sensor_stream_test PRIVATE -UNDEBUG -Wall -Wextra -Werror
    -Wno-unused-parameter)
target_link_libraries(sensor_stream_test PRIVATE Threads::Threads)
foreach(scenario parallel independent_links busy cancel cancel_deferred disconnect
        link_failure core_queue core_parallel)
    add_test(NAME sensor_stream_${scenario} COMMAND sensor_stream_test ${scenario})
    set_tests_properties(sensor_stream_${scenario} PROPERTIES TIMEOUT 10)
endforeach()

add_executable(sensor_stream_coalesced_test sensor_stream_test.c ../src/wendy_com_sensor.c
    ../../wendy_core/src/wendy_core_sensor.c ../src/sensorlink.pb.c
    ../../nanopb/pb_common.c ../../nanopb/pb_encode.c ../../nanopb/pb_decode.c)
target_include_directories(sensor_stream_coalesced_test PRIVATE sensor_stubs ../include
    ../../wendy_core/include ../../nanopb)
target_compile_definitions(sensor_stream_coalesced_test PRIVATE CONFIG_WENDY_SENSOR_LINK_XIAO_ESP32S3=1)
target_compile_options(sensor_stream_coalesced_test PRIVATE -UNDEBUG -Wall -Wextra -Werror -Wno-unused-parameter)
target_link_libraries(sensor_stream_coalesced_test PRIVATE Threads::Threads)
foreach(scenario parallel independent_links busy cancel cancel_deferred disconnect link_failure core_queue core_parallel)
    add_test(NAME sensor_coalesced_${scenario} COMMAND sensor_stream_coalesced_test ${scenario})
    set_tests_properties(sensor_coalesced_${scenario} PROPERTIES TIMEOUT 10)
endforeach()

add_executable(routed_stream_success_test routed_stream_success_test.c
    ../../wendy_net_peer/src/topology_record.c
    ../src/wendy_com_msg.pb.c ../src/sensorlink.pb.c
    ../../nanopb/pb_common.c ../../nanopb/pb_encode.c ../../nanopb/pb_decode.c)
target_include_directories(routed_stream_success_test PRIVATE stubs ../../wendy_pki/tests/stubs
    ../include ../../wendy_pki/include ../../wendy_conf/include ../../wendy_stdio/include ../../nanopb ../../wendy_net_common/include)
target_compile_definitions(routed_stream_success_test PRIVATE CONFIG_WENDY_COM_TASK_PRIORITY=1
    CONFIG_WENDY_COM_TASK_CORE_AFFINITY=0)
target_compile_options(routed_stream_success_test PRIVATE -UNDEBUG -Wall -Wextra -Werror
    -Wno-unused-parameter -Wno-unused-function)
add_test(NAME routed_stream_success COMMAND routed_stream_success_test)
set_tests_properties(routed_stream_success PROPERTIES TIMEOUT 10)

add_executable(topology_codec_success_test topology_codec_success_test.c
    ../../wendy_net_peer/src/topology_record.c
    ../src/wendy_com_msg.pb.c ../src/sensorlink.pb.c
    ../../nanopb/pb_common.c ../../nanopb/pb_encode.c ../../nanopb/pb_decode.c)
target_include_directories(topology_codec_success_test PRIVATE ../include ../../nanopb ../../wendy_net_common/include)
target_compile_options(topology_codec_success_test PRIVATE -UNDEBUG -Wall -Wextra -Werror)
add_test(NAME topology_codec_success COMMAND topology_codec_success_test "${CMAKE_CURRENT_LIST_DIR}/fixtures/topology_page.hex")
