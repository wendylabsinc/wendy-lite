cmake_minimum_required(VERSION 3.16)
project(wendy_com_sensor_test C)
set(CMAKE_C_STANDARD 11)
enable_testing()
find_package(Threads REQUIRED)

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
