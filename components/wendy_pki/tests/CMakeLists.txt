cmake_minimum_required(VERSION 3.20)
project(wendy_pki_test C)
set(ESP_PQC_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../esp-pqc" CACHE PATH "Pinned esp-pqc component")
set(MBEDTLS_ROOT "${ESP_PQC_ROOT}/components/mbedtls/mbedtls" CACHE PATH "Bundled PQC Mbed TLS 4 source directory")
set(OQS_ROOT "${ESP_PQC_ROOT}/components/liboqs/liboqs")
if(NOT EXISTS "${MBEDTLS_ROOT}/tf-psa-crypto/CMakeLists.txt" OR NOT EXISTS "${OQS_ROOT}/CMakeLists.txt")
    message(FATAL_ERROR "Initialize esp-pqc and its nested submodules: git submodule update --init --recursive components/esp-pqc")
endif()
find_package(Threads REQUIRED)
set(OQS_BUILD_ONLY_LIB ON CACHE BOOL "" FORCE)
set(OQS_USE_OPENSSL OFF CACHE BOOL "" FORCE)
set(OQS_DIST_BUILD OFF CACHE BOOL "" FORCE)
set(OQS_MINIMAL_BUILD "SIG_ml_dsa_65;SIG_ml_dsa_87" CACHE STRING "" FORCE)
# Prevent liboqs from imposing Release/-DNDEBUG on the firmware tests.
set(CMAKE_BUILD_TYPE None)
add_subdirectory("${OQS_ROOT}" liboqs EXCLUDE_FROM_ALL)
unset(CMAKE_BUILD_TYPE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(GEN_FILES OFF CACHE BOOL "Use the bundled generated Mbed TLS sources" FORCE)
add_subdirectory("${MBEDTLS_ROOT}" mbedtls)
include("${CMAKE_CURRENT_LIST_DIR}/../../../cmake/dependency_patches.cmake")
wendy_patch_mbedtls("${MBEDTLS_ROOT}")
# TF-PSA object libraries read crypto_config.h, not mbedtls_config.h. Match
# the TLS/X.509 key layout and enable the real OQS adapter in every library.
# Empty values match the bundled config's definitions without redefinition warnings.
foreach(target mbedtls mbedx509 tfpsacrypto builtin extras platform utilities everest p256-m)
    if(TARGET ${target})
        target_compile_definitions(${target} PUBLIC MBEDTLS_THREADING_C MBEDTLS_THREADING_PTHREAD
            MBEDTLS_SSL_TLS1_3_SIG_MLDSA65= MBEDTLS_X509_USE_C=)
        target_compile_definitions(${target} PUBLIC
            MBEDTLS_USER_CONFIG_FILE="${CMAKE_CURRENT_LIST_DIR}/mbedtls_user_config.h")
        target_include_directories(${target} PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/liboqs/include")
    endif()
endforeach()
target_link_libraries(tfpsacrypto PUBLIC oqs)
set(PKI_VERIFIER ../src/wendy_pki_verify.c)
set(PKI_TLS ../src/wendy_pki_tls.c)
add_library(pki STATIC ${PKI_VERIFIER} ../src/wendy_lite_grant.c ../src/wendy_lite_authority.c ../src/wendy_pki_crypto.c ../src/wendy_operator_auth.c ../src/wendy_pki_mesh_crypto.c)
target_include_directories(pki PUBLIC ../include stubs ../../wendy_conf/include ../../nanopb)
target_link_libraries(pki PUBLIC mbedtls mbedx509 tfpsacrypto Threads::Threads)
add_executable(crypto_test crypto_test.c)
target_link_libraries(crypto_test PRIVATE pki)
add_executable(verify_test verify_test.c)
target_link_libraries(verify_test PRIVATE pki)
add_executable(renewal_test renewal_test.c)
target_include_directories(renewal_test PRIVATE stubs ../include ../src
    ../../wendy_conf/include ../../nanopb)
target_sources(renewal_test PRIVATE ../src/wendy_pki_crypto.c)
target_link_libraries(renewal_test PRIVATE mbedtls mbedx509 tfpsacrypto)
add_executable(conf_test conf_test.c ../../wendy_conf/src/wendy_conf.pb.c
    ../../nanopb/pb_common.c ../../nanopb/pb_decode.c ../../nanopb/pb_encode.c)
target_include_directories(conf_test PRIVATE stubs ../../wendy_conf/include ../../nanopb)
target_link_libraries(conf_test PRIVATE Threads::Threads)
target_link_libraries(renewal_test PRIVATE Threads::Threads)
add_executable(mesh_identity_test renewal_test.c ../src/wendy_pki_crypto.c)
target_include_directories(mesh_identity_test PRIVATE stubs ../include ../src
    ../../wendy_conf/include ../../nanopb)
target_compile_definitions(mesh_identity_test PRIVATE CONFIG_WENDY_MESH_LEAF=1)
target_link_libraries(mesh_identity_test PRIVATE mbedtls mbedx509 tfpsacrypto Threads::Threads)

enable_testing()
add_test(NAME dependency_patches_in_checkout COMMAND "${CMAKE_COMMAND}" -P
    "${CMAKE_CURRENT_LIST_DIR}/../../../cmake/tests/dependency_patches_test.cmake")
add_test(NAME mesh_identity_persistence COMMAND mesh_identity_test "${CMAKE_CURRENT_LIST_DIR}/fixtures/device-key.der")
add_library(mesh_protocol STATIC ../../wendy_mesh/src/wendy_mesh_uplink_protocol.c ../../wendy_mesh/src/wendy_mesh_protocol.c ../../wendy_mesh/src/wendy_mesh_directory.c)
target_include_directories(mesh_protocol PUBLIC ../../wendy_mesh/include)
target_link_libraries(mesh_protocol PUBLIC pki)
target_compile_options(mesh_protocol PRIVATE -Wall -Wextra -Werror)
add_executable(mesh_fixture ../../wendy_mesh/tests/mesh_fixture.c)
target_link_libraries(mesh_fixture PRIVATE mesh_protocol)
add_executable(mesh_protocol_test ../../wendy_mesh/tests/protocol_test.c)
target_link_libraries(mesh_protocol_test PRIVATE mesh_protocol)
add_test(NAME mesh_protocol_bounds COMMAND mesh_protocol_test)
add_test(NAME pki_crypto_key_csr COMMAND crypto_test "${CMAKE_CURRENT_LIST_DIR}/fixtures/device-key.der")
add_test(NAME pki_verification COMMAND verify_test "${CMAKE_CURRENT_LIST_DIR}/fixtures")
add_test(NAME pki_verification_future_clock COMMAND verify_test "${CMAKE_CURRENT_LIST_DIR}/fixtures" 4102444800)
add_executable(public_time_test public_time_test.c)
target_link_libraries(public_time_test PRIVATE pki)
add_test(NAME pki_public_timestamp COMMAND public_time_test "${CMAKE_CURRENT_LIST_DIR}/public-time-fixtures")
add_test(NAME pki_public_timestamp_future_clock COMMAND public_time_test "${CMAKE_CURRENT_LIST_DIR}/public-time-fixtures" 4102444800)
add_test(NAME pki_renewal_fallback COMMAND renewal_test "${CMAKE_CURRENT_LIST_DIR}/fixtures/device-key.der")
set_tests_properties(pki_renewal_fallback PROPERTIES TIMEOUT 20)
add_test(NAME pki_configuration_persistence COMMAND conf_test)

# Exercise the production BLE session owner while injecting identity changes
# through its public PKI boundary. Real TLS verification is covered below.
add_executable(ble_tls_lifecycle_test ble_tls_lifecycle_test.c
    ../../wendy_ble/src/wendy_ble_tls.c)
target_include_directories(ble_tls_lifecycle_test PRIVATE stubs
    ../../wendy_ble/src ../../wendy_conf/include ../../nanopb)
target_compile_definitions(ble_tls_lifecycle_test PRIVATE
    CONFIG_WENDY_PKI=1 CONFIG_WENDY_BLE_REQUIRE_MTLS=0)
target_link_libraries(ble_tls_lifecycle_test PRIVATE pki)
add_test(NAME ble_tls_session_lifecycle COMMAND ble_tls_lifecycle_test)
add_executable(mldsa_test mldsa_test.c)
target_link_libraries(mldsa_test PRIVATE pki)
add_test(NAME pki_mldsa_verification COMMAND mldsa_test "${CMAKE_CURRENT_LIST_DIR}/mldsa-fixtures")
add_test(NAME pki_mldsa_verification_future_clock COMMAND mldsa_test "${CMAKE_CURRENT_LIST_DIR}/mldsa-fixtures" 4102444800)

add_executable(operator_test operator_test.c)
target_link_libraries(operator_test PRIVATE pki)
add_test(NAME pki_operator_identity COMMAND operator_test "${CMAKE_CURRENT_LIST_DIR}/operator-fixtures")

add_executable(lite_grant_test lite_grant_test.c)
target_link_libraries(lite_grant_test PRIVATE pki)
add_test(NAME lite_grant_verification COMMAND lite_grant_test "${CMAKE_CURRENT_LIST_DIR}/lite-fixtures")

set(IDF_COMPONENTS "$ENV{IDF_PATH}/components" CACHE PATH "ESP-IDF components used by host adapters")
if(NOT EXISTS "${IDF_COMPONENTS}/http_parser/http_parser.c")
    message(FATAL_ERROR "Set IDF_PATH to ESP-IDF 6.0.3, or set IDF_COMPONENTS to its components directory")
endif()
add_executable(tls_test tls_test.c ${PKI_TLS} "${IDF_COMPONENTS}/http_parser/http_parser.c")
# Only the host adapter interposes socket sends; production builds are unchanged.
set_source_files_properties(${PKI_TLS} PROPERTIES COMPILE_DEFINITIONS "send=wendy_test_send")
target_include_directories(tls_test PRIVATE stubs ../src ../../wendy_conf/include ../../nanopb "${IDF_COMPONENTS}/http_parser")
target_link_libraries(tls_test PRIVATE pki)
find_program(GO_EXECUTABLE go REQUIRED)
add_executable(mesh_crypto_test ../../wendy_mesh/tests/mesh_crypto_test.c)
target_link_libraries(mesh_crypto_test PRIVATE mesh_protocol)
add_executable(mesh_tls_test ../../wendy_mesh/tests/mesh_tls_test.c ${PKI_TLS} "${IDF_COMPONENTS}/http_parser/http_parser.c")
target_include_directories(mesh_tls_test PRIVATE ../src "${IDF_COMPONENTS}/http_parser")
target_link_libraries(mesh_tls_test PRIVATE mesh_protocol)
target_compile_definitions(mesh_tls_test PRIVATE WENDY_MESH_TEST_LOG=1)
add_test(NAME mesh_crypto_tls_interoperability COMMAND "${GO_EXECUTABLE}" run
    "${CMAKE_CURRENT_LIST_DIR}/../../wendy_mesh/tests/host_test_driver.go"
    "$<TARGET_FILE:mesh_crypto_test>" "$<TARGET_FILE:mesh_tls_test>")
set_tests_properties(mesh_crypto_tls_interoperability PROPERTIES TIMEOUT 90)
add_executable(lite_authority_test lite_authority_test.c)
target_link_libraries(lite_authority_test PRIVATE pki)
add_test(NAME lite_authority_policy COMMAND "${GO_EXECUTABLE}" run
    "${CMAKE_CURRENT_LIST_DIR}/lite_authority_test_driver.go"
    "$<TARGET_FILE:lite_authority_test>")
set_tests_properties(lite_authority_policy PROPERTIES TIMEOUT 30)
add_executable(operator_auth_test operator_auth_test.c)
target_link_libraries(operator_auth_test PRIVATE pki)
add_executable(operator_auth_tls_test operator_auth_tls_test.c)
target_link_libraries(operator_auth_tls_test PRIVATE pki)
add_test(NAME legacy_operator_authentication COMMAND "${GO_EXECUTABLE}" run
    "${CMAKE_CURRENT_LIST_DIR}/operator_auth_test_driver.go"
    "$<TARGET_FILE:operator_auth_test>" "$<TARGET_FILE:operator_auth_tls_test>")
# Hundreds of child-process handshakes take longer under address sanitization.
set_tests_properties(legacy_operator_authentication PROPERTIES TIMEOUT 240)
add_test(NAME pki_tls_interoperability COMMAND "${GO_EXECUTABLE}" run "${CMAKE_CURRENT_LIST_DIR}/tls_test_driver.go" "$<TARGET_FILE:tls_test>")
set_tests_properties(pki_tls_interoperability PROPERTIES TIMEOUT 90)
add_test(NAME pki_tls_mldsa65 COMMAND "${GO_EXECUTABLE}" run "${CMAKE_CURRENT_LIST_DIR}/tls_test_driver.go" "$<TARGET_FILE:tls_test>" "mldsa65")
set_tests_properties(pki_tls_mldsa65 PROPERTIES TIMEOUT 90)

# Compile the production capability helper under supported and disabled profiles.
add_library(capability_proto STATIC ../../wendy_com/src/wendy_com_msg.pb.c
    ../../wendy_com/src/sensorlink.pb.c
    ../../nanopb/pb_common.c ../../nanopb/pb_decode.c ../../nanopb/pb_encode.c)
target_include_directories(capability_proto PUBLIC ../../wendy_com/include ../../nanopb)
function(add_capabilities_test name pki cloud wifi mldsa65 reset_supported cloud_supported mldsa_supported)
    add_executable(${name} capabilities_test.c)
    target_link_libraries(${name} PRIVATE capability_proto)
    target_compile_definitions(${name} PRIVATE CONFIG_WENDY_PKI=${pki}
        CONFIG_WENDY_CLOUD=${cloud} CONFIG_WENDY_WIFI_ENABLED=${wifi}
        CONFIG_MBEDTLS_SSL_TLS1_3_SIG_MLDSA65=${mldsa65}
        EXPECT_RESET=${reset_supported} EXPECT_CLOUD=${cloud_supported}
        EXPECT_MLDSA=${mldsa_supported})
    add_test(NAME ${name} COMMAND ${name})
endfunction()
add_capabilities_test(enrollment_capabilities_enabled 1 1 1 0 1 1 0)
add_capabilities_test(enrollment_capabilities_cloud_disabled 1 0 1 0 1 0 0)
add_capabilities_test(enrollment_capabilities_wifi_disabled 1 1 0 0 1 0 0)
add_capabilities_test(enrollment_capabilities_pki_disabled 0 1 1 0 0 0 0)
add_capabilities_test(enrollment_capabilities_mldsa65 1 1 1 1 1 1 1)
add_capabilities_test(enrollment_capabilities_mldsa65_pki_disabled 0 1 1 1 0 0 0)

add_executable(link_permissions_test ../../wendy_com/tests/permissions_test.c)
target_include_directories(link_permissions_test PRIVATE ../../wendy_com/tests/stubs stubs
    ../include ../../wendy_conf/include ../../wendy_stdio/include)
target_compile_definitions(link_permissions_test PRIVATE CONFIG_WENDY_COM_TASK_PRIORITY=1
    CONFIG_WENDY_COM_TASK_CORE_AFFINITY=0)
target_link_libraries(link_permissions_test PRIVATE capability_proto mbedtls)
add_test(NAME wendycom_link_permissions COMMAND link_permissions_test)

add_executable(tx_stall_test ../../wendy_com/tests/tx_stall_test.c)
target_include_directories(tx_stall_test PRIVATE ../../wendy_com/tests/stubs stubs)
target_compile_definitions(tx_stall_test PRIVATE CONFIG_WENDY_COM_TASK_PRIORITY=1
    CONFIG_WENDY_COM_TASK_CORE_AFFINITY=0)
target_compile_options(tx_stall_test PRIVATE -UNDEBUG)
target_link_libraries(tx_stall_test PRIVATE capability_proto mbedtls)
foreach(scenario socket stream want_read no_bytes progress uart_initial uart_full uart_want_read)
    add_test(NAME wendycom_tx_stall_${scenario} COMMAND tx_stall_test ${scenario})
    set_tests_properties(wendycom_tx_stall_${scenario} PROPERTIES TIMEOUT 5)
endforeach()

add_executable(mesh_datagram_test ../../wendy_mesh/tests/datagram_test.c
    ../../wendy_mesh/src/wendy_mesh_datagram.c)
target_include_directories(mesh_datagram_test PRIVATE ../../wendy_mesh/include)
target_compile_options(mesh_datagram_test PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME mesh_datagram_reliability COMMAND mesh_datagram_test)

add_executable(mesh_uplink_protocol_test ../../wendy_mesh/tests/uplink_test.c)
target_link_libraries(mesh_uplink_protocol_test PRIVATE mesh_protocol)
target_compile_options(mesh_uplink_protocol_test PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME mesh_uplink_packets COMMAND mesh_uplink_protocol_test)
add_executable(dns_probe_test dns_probe_test.c)
target_include_directories(dns_probe_test PRIVATE ../src)
target_compile_options(dns_probe_test PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME uplink_direct_dns_bounds COMMAND dns_probe_test)

add_executable(mesh_uplink_identity_test renewal_test.c ../src/wendy_pki_crypto.c)
target_include_directories(mesh_uplink_identity_test PRIVATE stubs ../include ../src
    ../../wendy_conf/include ../../nanopb)
target_compile_definitions(mesh_uplink_identity_test PRIVATE CONFIG_WENDY_MESH_LEAF=1
    CONFIG_WENDY_MESH_CLOUD_UPLINK=1)
target_link_libraries(mesh_uplink_identity_test PRIVATE mbedtls mbedx509 tfpsacrypto Threads::Threads)
add_test(NAME mesh_uplink_identity_lifecycle COMMAND mesh_uplink_identity_test
    "${CMAKE_CURRENT_LIST_DIR}/fixtures/device-key.der")
