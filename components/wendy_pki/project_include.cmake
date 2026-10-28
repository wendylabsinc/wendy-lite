# Existing enrollments chain through ML-DSA-87 CAs. Set this before esp-pqc's
# component CMake runs so its minimal-common default does not disable the
# verifier. Standalone apps that depend on Wendy PKI need the same selection.
set(OQS_ENABLE_SIG_ml_dsa_87 "${CONFIG_MBEDTLS_SSL_TLS1_3_SIG_MLDSA65}"
    CACHE BOOL "Wendy CA verification" FORCE)

# The Mbed TLS targets do not exist yet. Patch them once the project's
# top-level CMakeLists.txt has finished, so every app using Wendy PKI gets the
# fixes without calling anything itself.
include("${CMAKE_CURRENT_LIST_DIR}/cmake/pqc_patches.cmake")
cmake_language(DEFER DIRECTORY "${CMAKE_SOURCE_DIR}" CALL wendy_pki_patch_bundled_mbedtls)
