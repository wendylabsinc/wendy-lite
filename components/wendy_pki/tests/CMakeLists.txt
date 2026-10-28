cmake_minimum_required(VERSION 3.20)
project(wendy_pki_test C)
# Test the esp-pqc revision that the firmware gets through wendy_pki's manifest.
file(STRINGS "${CMAKE_CURRENT_LIST_DIR}/../idf_component.yml" esp_pqc_version
    REGEX "^ +version: \"[0-9a-f]+\"$")
string(REGEX REPLACE "^ +version: \"([0-9a-f]+)\"$" "\\1" esp_pqc_version "${esp_pqc_version}")
if(NOT esp_pqc_version MATCHES "^[0-9a-f]+$")
    message(FATAL_ERROR "Cannot read the esp-pqc revision from wendy_pki/idf_component.yml")
endif()
include(FetchContent)
# esp-pqc is an ESP-IDF component. A SOURCE_SUBDIR without CMakeLists.txt
# fetches it with its nested submodules, but does not add it to this project.
# Set FETCHCONTENT_SOURCE_DIR_ESP_PQC to use a local checkout instead.
FetchContent_Declare(esp_pqc
    GIT_REPOSITORY https://github.com/espressif/esp-pqc.git
    GIT_TAG "${esp_pqc_version}"
    SOURCE_SUBDIR fetch-only)
FetchContent_MakeAvailable(esp_pqc)
set(MBEDTLS_ROOT "${esp_pqc_SOURCE_DIR}/components/mbedtls/mbedtls")
set(OQS_ROOT "${esp_pqc_SOURCE_DIR}/components/liboqs/liboqs")
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
        target_compile_definitions(${target} PUBLIC MBEDTLS_THREADING_C MBEDTLS_THREADING_PTHREAD MBEDTLS_PLATFORM_MEMORY=
            MBEDTLS_SSL_TLS1_3_SIG_MLDSA65= MBEDTLS_X509_USE_C=)
        target_compile_definitions(${target} PUBLIC
            MBEDTLS_USER_CONFIG_FILE="${CMAKE_CURRENT_LIST_DIR}/mbedtls_user_config.h")
        target_include_directories(${target} PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/liboqs/include")
    endif()
endforeach()
target_link_libraries(tfpsacrypto PUBLIC oqs)
set(PKI_VERIFIER ../src/wendy_pki_verify.c)
set(PKI_TLS ../src/wendy_pki_tls.c)
add_library(cert_bundle STATIC ../../wendy_conf/src/wendy_cert_bundle.c)
target_include_directories(cert_bundle PUBLIC ../../wendy_conf/include)
target_link_libraries(cert_bundle PUBLIC tfpsacrypto)
add_library(net_common STATIC ../../wendy_net_common/src/memory.c ../../wendy_net_common/src/runtime_memory.c ../../wendy_net_common/src/binary.c)
target_include_directories(net_common PUBLIC ../../wendy_net_common/include)
target_link_libraries(net_common PUBLIC Threads::Threads)
add_library(pki STATIC ../src/wendy_pki_issuers.c ../src/wendy_pki_work.c ../src/wendy_pki_tls_input.c ../src/wendy_pki_public_read.c ../src/wendy_pki_public_index.c ${PKI_VERIFIER} ../src/wendy_lite_grant.c ../src/wendy_lite_authority.c ../src/wendy_pki_crypto.c ../src/wendy_operator_auth.c ../src/wendy_pki_mesh_crypto.c)
target_include_directories(pki PUBLIC ../include stubs ../../wendy_conf/include ../../nanopb)
target_compile_definitions(pki PUBLIC CONFIG_WENDY_MESH_LEAF=1 WENDY_PKI_MEMORY_HOST_SCOPE_TEST=1)
target_link_libraries(pki PUBLIC net_common cert_bundle mbedtls mbedx509 tfpsacrypto Threads::Threads)
add_executable(crypto_test crypto_test.c)
target_link_libraries(crypto_test PRIVATE pki)
add_executable(verify_test verify_test.c)
target_link_libraries(verify_test PRIVATE pki)
add_executable(renewal_test renewal_test.c)
target_include_directories(renewal_test PRIVATE ../../wendy_net_common/include stubs ../include ../src
    ../../wendy_conf/include ../../nanopb)
target_sources(renewal_test PRIVATE ../src/wendy_pki_crypto.c)
target_link_libraries(renewal_test PRIVATE mbedtls mbedx509 tfpsacrypto)
add_executable(conf_test conf_test.c ../../wendy_conf/src/wendy_conf.pb.c
    ../../nanopb/pb_common.c ../../nanopb/pb_decode.c ../../nanopb/pb_encode.c)
target_compile_options(conf_test PRIVATE -UNDEBUG)
target_include_directories(conf_test PRIVATE stubs ../../wendy_conf/include ../../nanopb)
target_link_libraries(conf_test PRIVATE cert_bundle Threads::Threads)
target_link_libraries(renewal_test PRIVATE Threads::Threads)
add_executable(mesh_identity_test renewal_test.c ../src/wendy_pki_crypto.c)
target_include_directories(mesh_identity_test PRIVATE ../../wendy_net_common/include stubs ../include ../src
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
add_test(NAME pki_configuration_persistence COMMAND conf_test "${CMAKE_CURRENT_LIST_DIR}/fixtures")
add_executable(der_bundle_test der_bundle_test.c)
target_include_directories(der_bundle_test PRIVATE ../src)
target_link_libraries(der_bundle_test PRIVATE pki)
target_compile_options(der_bundle_test PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME pki_der_bundle_import COMMAND der_bundle_test "${CMAKE_CURRENT_LIST_DIR}/fixtures")

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
# Simulate control traffic and deadlines through the production relay loop.
add_executable(relay_control_test relay_control_test.c "${IDF_COMPONENTS}/http_parser/http_parser.c")
target_include_directories(relay_control_test PRIVATE stubs ../src "${IDF_COMPONENTS}/http_parser")
target_compile_options(relay_control_test PRIVATE -UNDEBUG)
target_link_libraries(relay_control_test PRIVATE pki)
add_test(NAME pki_relay_control_refresh COMMAND relay_control_test)
set_tests_properties(pki_relay_control_refresh PROPERTIES TIMEOUT 5)
add_executable(relay_stream_wait_test relay_stream_wait_test.c "${IDF_COMPONENTS}/http_parser/http_parser.c")
target_include_directories(relay_stream_wait_test PRIVATE stubs ../src "${IDF_COMPONENTS}/http_parser")
target_compile_options(relay_stream_wait_test PRIVATE -UNDEBUG)
target_link_libraries(relay_stream_wait_test PRIVATE pki)
add_test(NAME pki_relay_stream_deadlines COMMAND relay_stream_wait_test)
set_tests_properties(pki_relay_stream_deadlines PROPERTIES TIMEOUT 5)
add_executable(tls_uplink_test tls_test.c ${PKI_TLS} "${IDF_COMPONENTS}/http_parser/http_parser.c")
target_include_directories(tls_uplink_test PRIVATE stubs ../src ../../wendy_conf/include ../../nanopb "${IDF_COMPONENTS}/http_parser")
target_link_libraries(tls_uplink_test PRIVATE pki)
target_compile_definitions(tls_uplink_test PRIVATE CONFIG_WENDY_MESH_CLOUD_UPLINK=1)
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
# Linux router vectors made by the WendyOS manifest signer: ML-DSA-65 and P-256.
add_executable(mesh_mldsa_router_test ../../wendy_mesh/tests/mldsa_router_test.c)
target_link_libraries(mesh_mldsa_router_test PRIVATE mesh_protocol)
target_compile_options(mesh_mldsa_router_test PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME mesh_mldsa_router_manifests COMMAND mesh_mldsa_router_test
    "${CMAKE_CURRENT_LIST_DIR}/../../wendy_mesh/tests/mldsa-router-fixtures")
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
foreach(scenario socket stream want_read no_bytes progress uart_initial uart_full uart_cdc uart_want_read)
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
target_include_directories(mesh_uplink_identity_test PRIVATE ../../wendy_net_common/include stubs ../include ../src
    ../../wendy_conf/include ../../nanopb)
target_compile_definitions(mesh_uplink_identity_test PRIVATE CONFIG_WENDY_MESH_LEAF=1
    CONFIG_WENDY_MESH_CLOUD_UPLINK=1)
target_link_libraries(mesh_uplink_identity_test PRIVATE mbedtls mbedx509 tfpsacrypto Threads::Threads)
add_test(NAME mesh_uplink_identity_lifecycle COMMAND mesh_uplink_identity_test
    "${CMAKE_CURRENT_LIST_DIR}/fixtures/device-key.der")

add_test(NAME pki_tls_slow_cloud_uplink COMMAND "${GO_EXECUTABLE}" run "${CMAKE_CURRENT_LIST_DIR}/tls_test_driver.go" "$<TARGET_FILE:tls_uplink_test>" "p256" "slow-uplink")
set_tests_properties(pki_tls_slow_cloud_uplink PROPERTIES TIMEOUT 90)

add_executable(mesh_topology_test ../../wendy_mesh/tests/topology_test.c)
target_link_libraries(mesh_topology_test PRIVATE mesh_protocol)
target_compile_options(mesh_topology_test PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME mesh_topology_snapshot COMMAND mesh_topology_test)

add_executable(uart_cdc_test ../../wendy_com/tests/uart_cdc_test.c)
target_include_directories(uart_cdc_test PRIVATE stubs ../../wendy_com/include)
target_compile_options(uart_cdc_test PRIVATE -UNDEBUG -Wall -Wextra -Werror)
add_test(NAME wendycom_cdc_framing COMMAND uart_cdc_test)

add_executable(mesh_discovery_test ../../wendy_mesh/tests/discovery_test.c
    ../../wendy_mesh/src/wendy_mesh_discovery.c
    ../../wendy_mesh/src/wendy_mesh_discovery_protocol.c)
target_include_directories(mesh_discovery_test PRIVATE ../../wendy_mesh/tests/discovery_stubs)
target_link_libraries(mesh_discovery_test PRIVATE mesh_protocol)
target_compile_options(mesh_discovery_test PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME mesh_router_discovery COMMAND mesh_discovery_test)

add_executable(mesh_connect_test ../../wendy_mesh/tests/connect_test.c
    ../../wendy_mesh/src/wendy_mesh_connect.c)
target_include_directories(mesh_connect_test PRIVATE ../../wendy_wifi/include)
target_link_libraries(mesh_connect_test PRIVATE mesh_protocol)
target_compile_definitions(mesh_connect_test PRIVATE CONFIG_WENDY_MESH_WIFI_BLE=1
    CONFIG_WENDY_MESH_AUTO_DISCOVER=1 CONFIG_WENDY_MESH_ROUTER_PORT=43024)
target_compile_options(mesh_connect_test PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME mesh_transport_fallback COMMAND mesh_connect_test)

add_executable(tls_reassembly_test tls_reassembly_test.c)
target_include_directories(tls_reassembly_test PRIVATE "${CMAKE_BINARY_DIR}/wendy_patched/mbedtls/library" "${CMAKE_BINARY_DIR}/wendy_patched/mbedtls/tf-psa-crypto/core" "${CMAKE_BINARY_DIR}/wendy_patched/mbedtls/tf-psa-crypto/drivers/builtin/src" "$<TARGET_PROPERTY:mbedtls,INCLUDE_DIRECTORIES>")
target_link_libraries(tls_reassembly_test PRIVATE pki)
add_test(NAME tls_record_reassembly COMMAND tls_reassembly_test --normal-preallocated)
add_test(NAME tls_record_recycle COMMAND tls_reassembly_test --normal-recycle)
foreach(fixture tls_input_workspace tls_input_management_loan)
    add_executable(${fixture}_test ${fixture}_success_test.c ../src/wendy_pki_tls_input.c)
    target_include_directories(${fixture}_test BEFORE PRIVATE input_stubs ../src)
    target_link_libraries(${fixture}_test PRIVATE net_common)
    add_test(NAME ${fixture}_ownership COMMAND ${fixture}_test)
endforeach()
add_executable(psa_global_tables_test psa_global_tables_success_test.c)
target_link_libraries(psa_global_tables_test PRIVATE pki)
add_test(NAME psa_global_table_ownership COMMAND psa_global_tables_test)

foreach(profile p256 mldsa65)
    add_test(NAME pki_owned_der_stream_${profile} COMMAND "${GO_EXECUTABLE}" run
        "${CMAKE_CURRENT_LIST_DIR}/tls_test_driver.go" "$<TARGET_FILE:tls_test>" ${profile})
    set_tests_properties(pki_owned_der_stream_${profile} PROPERTIES TIMEOUT 90
        ENVIRONMENT "WENDY_TLS_OWNED_STREAM=1;WENDY_TLS_OWNED_ONLY=1;WENDY_TLS_SCOPED_OWNER=1")
endforeach()

add_executable(der_cache_test der_cache_test.c ../src/wendy_pki_der_cache.c)
target_include_directories(der_cache_test PRIVATE ../src)
target_link_libraries(der_cache_test PRIVATE pki)
target_compile_options(der_cache_test PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME pki_own_der_cache COMMAND der_cache_test "${CMAKE_CURRENT_LIST_DIR}/fixtures/identity.pem")
add_executable(tls_input_epoch_test tls_input_epoch_test.c ../src/wendy_pki_tls_input.c)
target_include_directories(tls_input_epoch_test BEFORE PRIVATE input_stubs ../src)
target_link_libraries(tls_input_epoch_test PRIVATE net_common)
add_test(NAME tls_input_epoch_ownership COMMAND tls_input_epoch_test)

add_test(NAME tls_pending_output_compaction COMMAND tls_reassembly_test --pending-output)
add_executable(artifact_domain_test artifact_domain_test.c)
target_include_directories(artifact_domain_test PRIVATE ../src)
target_link_libraries(artifact_domain_test PRIVATE pki)
add_test(NAME native_artifact_domain_with_legacy_leaf COMMAND artifact_domain_test)

add_test(NAME pki_normal_der_roots COMMAND verify_test --normal-roots "${CMAKE_CURRENT_LIST_DIR}/fixtures")

add_test(NAME pki_own_boot_persistence COMMAND mesh_identity_test
    "${CMAKE_CURRENT_LIST_DIR}/fixtures/device-key.der" --normal-boot-persistence)

# Optional normal interop against the canonical, unchanged WendyOS helpers.
add_executable(issuer_interop_success_test issuer_interop_success_test.c ${PKI_TLS}
    "${IDF_COMPONENTS}/http_parser/http_parser.c")
target_include_directories(issuer_interop_success_test PRIVATE ../src "${IDF_COMPONENTS}/http_parser")
target_link_libraries(issuer_interop_success_test PRIVATE pki)
target_compile_definitions(issuer_interop_success_test PRIVATE WENDY_MESH_TEST_LOG=1)
target_compile_options(issuer_interop_success_test PRIVATE -Wall -Wextra -Werror -UNDEBUG)
set(WENDYOS_GO_ROOT "" CACHE PATH "Optional WendyOS module root for issuer ALPN interop")
if(WENDYOS_GO_ROOT)
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    add_test(NAME pki_issuer_wos_interop_normal COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_LIST_DIR}/issuer_wos_interop.py" --go "${GO_EXECUTABLE}"
        --wendyos-root "${WENDYOS_GO_ROOT}" --driver "$<TARGET_FILE:issuer_interop_success_test>")
    set_tests_properties(pki_issuer_wos_interop_normal PROPERTIES TIMEOUT 120)
endif()

add_executable(issuer_helpers_test issuer_helpers_test.c)
target_include_directories(issuer_helpers_test PRIVATE ../src)
target_link_libraries(issuer_helpers_test PRIVATE pki)
target_compile_options(issuer_helpers_test PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME pki_issuer_helpers_normal COMMAND issuer_helpers_test)

# Already-trimmed own DER sources must retain pinned non-root intermediates.
foreach(profile p256 mldsa65)
    add_test(NAME pki_owned_der_source_without_root_${profile} COMMAND "${GO_EXECUTABLE}" run
        "${CMAKE_CURRENT_LIST_DIR}/tls_test_driver.go" "$<TARGET_FILE:tls_test>" ${profile})
    set_tests_properties(pki_owned_der_source_without_root_${profile} PROPERTIES TIMEOUT 90
        ENVIRONMENT "WENDY_TLS_OWNED_STREAM=1;WENDY_TLS_OWNED_ONLY=1;WENDY_TLS_SCOPED_OWNER=1;WENDY_TLS_SOURCE_ROOT_OMITTED=1")
endforeach()
# Standalone production-dispatcher lifecycle/ownership coverage, also usable
# without configuring the certificate/crypto libraries.
add_subdirectory(work)

add_executable(native_agent_success_test ../../wendy_net_peer/tests/native_agent_success_test.c
    ../../wendy_net_peer/src/agent_bridge.c ../../wendy_net_peer/src/agent_pipe.c
    ../../wendy_net_peer/src/actor.c ../../wendy_net_common/src/memory.c
    ../../wendy_net_common/src/runtime_memory.c)
target_include_directories(native_agent_success_test PRIVATE ../../wendy_net_peer/include
    ../../wendy_net_peer/src ../../wendy_net_common/include ../../wendy_com/include
    ../include stubs ../../wendy_conf/include ../../nanopb)
target_compile_definitions(native_agent_success_test PRIVATE WENDY_NET_MEMORY_HOST_BUDGET_TEST=1
    CONFIG_WENDY_NET_TCP_RELAY_BUFFER_SIZE=256)
target_link_libraries(native_agent_success_test PRIVATE Threads::Threads)
target_compile_options(native_agent_success_test PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME native_agent_success COMMAND native_agent_success_test)


add_library(native_agent_com_backend OBJECT native_agent_com_backend.c
    ../../wendy_com/src/wendy_com_sensor.c ../../wendy_com/src/wendy_com_msg.pb.c
    ../../wendy_com/src/sensorlink.pb.c ../../nanopb/pb_common.c
    ../../nanopb/pb_encode.c ../../nanopb/pb_decode.c)
target_include_directories(native_agent_com_backend PRIVATE ../../wendy_com/tests/stubs stubs
    ../../wendy_com/include ../include ../../wendy_conf/include ../../wendy_stdio/include ../../nanopb)
target_compile_definitions(native_agent_com_backend PRIVATE CONFIG_WENDY_COM_TASK_PRIORITY=1
    CONFIG_WENDY_COM_TASK_CORE_AFFINITY=0)
target_compile_options(native_agent_com_backend PRIVATE -UNDEBUG -Wall -Wextra -Werror
    -Wno-unused-parameter -Wno-unused-function)
add_executable(native_agent_composed_test native_agent_composed_test.c ${PKI_TLS}
    "${IDF_COMPONENTS}/http_parser/http_parser.c" $<TARGET_OBJECTS:native_agent_com_backend>
    ../../wendy_net_peer/src/agent_bridge.c ../../wendy_net_peer/src/agent_pipe.c
    ../../wendy_net_peer/src/actor.c ../../wendy_net_common/src/runtime_memory.c)
target_include_directories(native_agent_composed_test PRIVATE ../src ../../wendy_net_peer/include
    ../../wendy_net_peer/src ../../wendy_com/include "${IDF_COMPONENTS}/http_parser")
target_compile_definitions(native_agent_composed_test PRIVATE WENDY_NET_MEMORY_HOST_BUDGET_TEST=1
    WENDY_PKI_INPUT_SHRINK_HOST_TEST=1 WENDY_MESH_TEST_LOG=1 CONFIG_WENDY_NET_TCP_RELAY_BUFFER_SIZE=256)
target_compile_options(native_agent_composed_test PRIVATE -UNDEBUG -Wall -Wextra -Werror -Wno-unused-parameter -Wno-unused-function)
target_link_libraries(native_agent_composed_test PRIVATE pki)
foreach(profile p256 mldsa65)
    add_test(NAME pki_native_agent_composed_${profile} COMMAND "${GO_EXECUTABLE}" run
        "${CMAKE_CURRENT_LIST_DIR}/native_agent_composed_driver.go"
        "${CMAKE_CURRENT_LIST_DIR}/native_agent_composed_client.go"
        "$<TARGET_FILE:native_agent_composed_test>" ${profile})
    set_tests_properties(pki_native_agent_composed_${profile} PROPERTIES TIMEOUT 90
        WORKING_DIRECTORY "${CMAKE_CURRENT_LIST_DIR}/../../../go/console/wendypb"
        ENVIRONMENT "WENDY_TLS_OWNED_STREAM=1;WENDY_TLS_NORMAL_ONLY=1;WENDY_TLS_DER_RANGES=1;WENDY_TLS_BOUNDED_SOURCE_HASH=1;WENDY_TLS_AGENT_ACTOR=1;WENDY_TLS_OPERATOR_OPAQUE=1;WENDY_TLS_AGENT_COMPOSED=1")
endforeach()

add_executable(native_prepare_success_test native_prepare_success_test.c ../src/wendy_pki_work.c
    ../../wendy_net_common/src/memory.c ../../wendy_net_common/src/runtime_memory.c)
target_include_directories(native_prepare_success_test PRIVATE ../src ../include stubs
    ../../wendy_net_common/include ../../wendy_conf/include ../../nanopb)
target_compile_definitions(native_prepare_success_test PRIVATE WENDY_NET_MEMORY_HOST_BUDGET_TEST=1)
target_compile_options(native_prepare_success_test PRIVATE -UNDEBUG -Wall -Wextra -Werror)
target_link_libraries(native_prepare_success_test PRIVATE Threads::Threads)
add_test(NAME native_prepare_success COMMAND native_prepare_success_test)

add_executable(handshake_admission_success_test handshake_admission_success_test.c ../src/wendy_pki_work.c
    ../../wendy_net_peer/src/actor.c ../../wendy_net_common/src/memory.c ../../wendy_net_common/src/runtime_memory.c)
target_include_directories(handshake_admission_success_test PRIVATE ../include ../../wendy_net_peer/include ../../wendy_net_common/include)
target_link_libraries(handshake_admission_success_test PRIVATE Threads::Threads)
target_compile_options(handshake_admission_success_test PRIVATE -UNDEBUG -Wall -Wextra -Werror)
add_test(NAME handshake_admission_success COMMAND handshake_admission_success_test)


add_executable(carrier_three_tls_success_test carrier_three_tls_success_test.c ${PKI_TLS}
    ../../wendy_net_common/src/runtime_memory.c ../../wendy_net_peer/src/packet.c
    ../../wendy_net_peer/src/actor.c ../../wendy_net_peer/src/carrier.c
    ../../wendy_net_peer/src/protocol.c ../../wendy_net_peer/src/binary.c
    "${IDF_COMPONENTS}/http_parser/http_parser.c")
target_include_directories(carrier_three_tls_success_test PRIVATE ../src ../../wendy_net_peer/include
    "${IDF_COMPONENTS}/http_parser")
target_compile_definitions(carrier_three_tls_success_test PRIVATE WENDY_NET_MEMORY_HOST_BUDGET_TEST=1 WENDY_MESH_TEST_LOG=1
    WNA_IO_BYTES=512)
target_compile_options(carrier_three_tls_success_test PRIVATE -UNDEBUG -Wall -Wextra -Werror -Wno-unused-parameter -Wno-unused-function)
target_link_libraries(carrier_three_tls_success_test PRIVATE pki)
foreach(profile p256 mldsa65)
    add_test(NAME carrier_three_tls_${profile}_success COMMAND "${GO_EXECUTABLE}" run
        "${CMAKE_CURRENT_LIST_DIR}/carrier_three_tls_success_driver.go"
        "$<TARGET_FILE:carrier_three_tls_success_test>" ${profile})
    set_tests_properties(carrier_three_tls_${profile}_success PROPERTIES TIMEOUT 90
        WORKING_DIRECTORY "${CMAKE_CURRENT_LIST_DIR}")
endforeach()

add_executable(app_actor_success_test ../../wendy_net_peer/tests/app_actor_success_test.c
    ../../wendy_net_peer/src/actor.c ../../wendy_net_peer/src/protocol.c ../../wendy_net_peer/src/binary.c
    ../../wendy_net_common/src/binary.c ../../wendy_net_common/src/memory.c ../../wendy_net_common/src/runtime_memory.c)
target_include_directories(app_actor_success_test BEFORE PRIVATE ../../wendy_net_peer/tests/app_stubs
    ../../wendy_net_peer/tests/io_stubs ../../wendy_net_peer/tests/router_stubs)
target_include_directories(app_actor_success_test PRIVATE ../../wendy_net_peer/include
    ../../wendy_net_peer/src ../../wendy_net_common/include ../../wendy_net/include
    ../include stubs ../../wendy_conf/include ../../nanopb)
target_compile_definitions(app_actor_success_test PRIVATE WENDY_NET_MEMORY_HOST_BUDGET_TEST=1
    CONFIG_WENDY_NET=1 CONFIG_WENDY_NET_CONSTRAINED_PROFILE=1 CONFIG_WENDY_NET_APP_MAX_FLOWS=2
    CONFIG_WENDY_NET_TCP_RELAY_BUFFER_SIZE=256)
target_compile_options(app_actor_success_test PRIVATE -Wall -Wextra -Werror -Wno-unused-parameter -Wno-unused-function -UNDEBUG)
target_link_libraries(app_actor_success_test PRIVATE Threads::Threads)
add_test(NAME native_app_actor_success COMMAND app_actor_success_test)

find_package(Python3 REQUIRED COMPONENTS Interpreter)
set(carrier_loan_callbacks "${CMAKE_CURRENT_BINARY_DIR}/carrier_loan_callbacks.inc")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_LIST_DIR}/../../wendy_net_peer/src/peer.c"
    "${CMAKE_CURRENT_LIST_DIR}/../../wendy_net_peer/src/router_session.c"
    "${CMAKE_CURRENT_LIST_DIR}/../../wendy_net_peer/src/catalog_node.c"
    "${CMAKE_CURRENT_LIST_DIR}/../../../cmake/tests/generate_carrier_loan_fixture.py")
execute_process(COMMAND "${Python3_EXECUTABLE}"
    "${CMAKE_CURRENT_LIST_DIR}/../../../cmake/tests/generate_carrier_loan_fixture.py"
    "${carrier_loan_callbacks}" COMMAND_ERROR_IS_FATAL ANY)
add_executable(carrier_signing_loan_success_test carrier_signing_loan_success_test.c
    ../../wendy_net_peer/src/carrier.c ../../wendy_net_peer/src/crypto_job.c
    ../../wendy_net_peer/src/protocol.c ../../wendy_net_peer/src/binary.c ../../wendy_net_peer/src/certificate_wire.c
    ../../wendy_net_peer/src/service_store.c ../../wendy_net_peer/src/service_protocol.c ../../wendy_net_peer/src/manifest_service.c
    ../../wendy_net_peer/src/packet.c ../../wendy_net_common/src/runtime_memory.c)
target_include_directories(carrier_signing_loan_success_test PRIVATE
    "${CMAKE_CURRENT_BINARY_DIR}" ../../wendy_net_peer/include ../../wendy_net_peer/src
    ../../wendy_net_gossip/include)
target_compile_definitions(carrier_signing_loan_success_test PRIVATE
    WENDY_NET_ROUTE_CRYPTO_HOST_TEST=1 WENDY_NET_MEMORY_HOST_BUDGET_TEST=1)
target_compile_options(carrier_signing_loan_success_test PRIVATE -Wall -Wextra -Werror -UNDEBUG)
target_link_libraries(carrier_signing_loan_success_test PRIVATE pki)
add_test(NAME carrier_signing_loan_success COMMAND carrier_signing_loan_success_test
    "${CMAKE_CURRENT_LIST_DIR}/fixtures/device-key.der")
set_tests_properties(carrier_signing_loan_success PROPERTIES TIMEOUT 15)
add_test(NAME carrier_signing_with_tls_workspace COMMAND carrier_signing_loan_success_test
    "${CMAKE_CURRENT_LIST_DIR}/fixtures/device-key.der" tls-overlap)
set_tests_properties(carrier_signing_with_tls_workspace PROPERTIES TIMEOUT 15)
# Normal random RFC3161 nonce integer shapes, including sign/zero padding.
find_package(Python3 REQUIRED COMPONENTS Interpreter)
add_executable(time_nonce_success_test time_nonce_success_test.c)
target_link_libraries(time_nonce_success_test PRIVATE pki)
target_compile_options(time_nonce_success_test PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME pki_time_nonce_normal COMMAND "${Python3_EXECUTABLE}"
    "${CMAKE_CURRENT_LIST_DIR}/time_nonce_success.py" "${GO_EXECUTABLE}"
    "${CMAKE_CURRENT_LIST_DIR}/public_time_fixtures.go" "$<TARGET_FILE:time_nonce_success_test>")
set_tests_properties(pki_time_nonce_normal PROPERTIES TIMEOUT 240)
