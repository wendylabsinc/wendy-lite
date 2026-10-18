cmake_minimum_required(VERSION 3.16)
project(wendy_stdio_test C)
set(CMAKE_C_STANDARD 11)
enable_testing()

foreach(owned_uart 0 1)
    add_executable(stdio_test_${owned_uart} stdio_test.c)
    target_include_directories(stdio_test_${owned_uart} PRIVATE stubs ../include)
    target_compile_definitions(stdio_test_${owned_uart} PRIVATE
        CONFIG_WENDY_USJ_USE_UART=${owned_uart})
    target_compile_options(stdio_test_${owned_uart} PRIVATE -UNDEBUG -Wall -Wextra
        -Werror -Wno-unused-parameter)
    foreach(scenario output input flags metadata)
        add_test(NAME stdio_${owned_uart}_${scenario}
            COMMAND stdio_test_${owned_uart} ${scenario})
        set_tests_properties(stdio_${owned_uart}_${scenario} PROPERTIES TIMEOUT 10)
    endforeach()
endforeach()
