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
