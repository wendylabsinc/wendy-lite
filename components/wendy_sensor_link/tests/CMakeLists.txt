cmake_minimum_required(VERSION 3.16)
project(wendy_sensor_link_test C)
set(CMAKE_C_STANDARD 11)
enable_testing()

add_executable(sensor_link_test sensor_link_test.c
    ../src/wendy_sensor_link.c ../src/cam_loop.c)
target_include_directories(sensor_link_test PRIVATE stubs ../include ../src
    ../../wendy_core/include ../../wendy_com/include ../../nanopb)
target_compile_options(sensor_link_test PRIVATE -UNDEBUG -Wall -Wextra -Werror
    -Wno-unused-parameter)

foreach(scenario manifest_both manifest_camera_only manifest_microphone_only
        no_sensors_retry event_group_failure_retry sender_task_failure_retry
        subscription_lifecycle camera_frame_lifetime microphone_frame_lifetime
        stream_begin_failure microphone_start_failure stats_completion stats_rejection
        stats_inline_completion stats_capture_failure)
    add_test(NAME sensor_link_${scenario} COMMAND sensor_link_test ${scenario})
    set_tests_properties(sensor_link_${scenario} PROPERTIES TIMEOUT 5)
endforeach()

find_package(Threads REQUIRED)
add_executable(korvo_sender_test korvo_sender_test.c
    ../src/wendy_sensor_link.c ../src/cam_loop.c)
target_include_directories(korvo_sender_test PRIVATE stubs ../include ../src
    ../../wendy_core/include ../../wendy_com/include ../../nanopb)
target_compile_definitions(korvo_sender_test PRIVATE
    CONFIG_WENDY_SENSOR_LINK_ESP32S31_KORVO_1=1 SENSOR_LINK_TEST_THREADS=1)
target_compile_options(korvo_sender_test PRIVATE -UNDEBUG -Wall -Wextra -Werror
    -Wno-unused-parameter)
target_link_libraries(korvo_sender_test PRIVATE Threads::Threads)
foreach(scenario concurrent second_task_failure)
    add_test(NAME sensor_link_korvo_${scenario} COMMAND korvo_sender_test ${scenario})
    set_tests_properties(sensor_link_korvo_${scenario} PROPERTIES TIMEOUT 5)
endforeach()
