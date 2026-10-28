cmake_minimum_required(VERSION 3.16)
project(wendy_server_tls_test C)
set(CMAKE_C_STANDARD 11)
enable_testing()

add_executable(anonymous_tls_test anonymous_tls_test.c ../src/wendy_server_tls.c)
target_include_directories(anonymous_tls_test PRIVATE stubs ../src
    ../../wendy_pki/tests/stubs ../../wendy_pki/include
    ../../wendy_conf/include ../../wendy_com/include ../../nanopb)
target_compile_options(anonymous_tls_test PRIVATE -UNDEBUG -Wall -Wextra -Werror)
add_test(NAME anonymous_lan_enrollment_guards COMMAND anonymous_tls_test)

add_executable(mesh_classification_success_test mesh_classification_success_test.c)
target_include_directories(mesh_classification_success_test PRIVATE ../src)
target_compile_options(mesh_classification_success_test PRIVATE -UNDEBUG -Wall -Wextra -Werror)
add_test(NAME server_normal_mesh_classification COMMAND mesh_classification_success_test)

add_executable(pending_success_test pending_success_test.c)
target_include_directories(pending_success_test PRIVATE ../src)
target_compile_options(pending_success_test PRIVATE -UNDEBUG -Wall -Wextra -Werror)
add_test(NAME server_physical_deferred_admission COMMAND pending_success_test)
