cmake_minimum_required(VERSION 3.16)
project(wendy_sensor_link_test C)
set(CMAKE_C_STANDARD 11)
enable_testing()
find_package(Threads REQUIRED)

add_executable(sensor_link_test sensor_link_test.c
    ../src/wendy_sensor_link.c ../src/cam_loop.c)
target_include_directories(sensor_link_test PRIVATE stubs ../include ../src
    ../../wendy_core/include ../../wendy_com/include ../../nanopb)
target_compile_options(sensor_link_test PRIVATE -UNDEBUG -Wall -Wextra -Werror
    -Wno-unused-parameter)

foreach(scenario manifest_both manifest_camera_only manifest_microphone_only
        no_sensors_retry event_group_failure_retry sender_task_failure_retry
        subscription_lifecycle camera_frame_lifetime microphone_frame_lifetime
        stream_begin_failure microphone_start_failure microphone_catches_up
        microphone_catch_up_bounded stats_completion stats_rejection
        stats_inline_completion stats_capture_failure)
    add_test(NAME sensor_link_${scenario} COMMAND sensor_link_test ${scenario})
    set_tests_properties(sensor_link_${scenario} PROPERTIES TIMEOUT 5)
endforeach()

# Exercise the actual Mosaico capture worker with a controlled camera and
# encoder, including a transport that holds its JPEG across many captures.
add_executable(mosaico_camera_test mosaico_camera_test.c ../src/mosaico_camera.c)
target_include_directories(mosaico_camera_test PRIVATE stubs ../src)
target_compile_definitions(mosaico_camera_test PRIVATE
    CONFIG_WENDY_SENSOR_LINK_MOSAICO=1 SENSOR_LINK_TEST_THREADS=1)
target_compile_options(mosaico_camera_test PRIVATE -UNDEBUG -Wall -Wextra -Werror
    -Wno-unused-parameter)
target_link_libraries(mosaico_camera_test PRIVATE Threads::Threads)
foreach(scenario latest errors stop_encoding init_failure)
    add_test(NAME mosaico_camera_${scenario} COMMAND mosaico_camera_test ${scenario})
    set_tests_properties(mosaico_camera_${scenario} PROPERTIES TIMEOUT 5)
endforeach()

foreach(board korvo xiao mosaico)
    add_executable(${board}_sender_test concurrent_sender_test.c
        ../src/wendy_sensor_link.c ../src/cam_loop.c)
    target_include_directories(${board}_sender_test PRIVATE stubs ../include ../src
        ../../wendy_core/include ../../wendy_com/include ../../nanopb)
    target_compile_definitions(${board}_sender_test PRIVATE SENSOR_LINK_TEST_THREADS=1)
    target_compile_options(${board}_sender_test PRIVATE -UNDEBUG -Wall -Wextra -Werror
        -Wno-unused-parameter)
    target_link_libraries(${board}_sender_test PRIVATE Threads::Threads)
    foreach(scenario concurrent second_task_failure)
        add_test(NAME sensor_link_${board}_${scenario} COMMAND ${board}_sender_test ${scenario})
        set_tests_properties(sensor_link_${board}_${scenario} PROPERTIES TIMEOUT 5)
    endforeach()
endforeach()
target_compile_definitions(korvo_sender_test PRIVATE CONFIG_WENDY_SENSOR_LINK_ESP32S31_KORVO_1=1)
target_compile_definitions(mosaico_sender_test PRIVATE CONFIG_WENDY_SENSOR_LINK_MOSAICO=1)
