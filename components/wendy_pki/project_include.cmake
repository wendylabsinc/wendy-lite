# Existing enrollments chain through ML-DSA-87 CAs. Set this before esp-pqc's
# component CMake runs so its minimal-common default does not disable the
# verifier. Standalone apps that depend on Wendy PKI need the same selection.
set(OQS_ENABLE_SIG_ml_dsa_87 "${CONFIG_MBEDTLS_SSL_TLS1_3_SIG_MLDSA65}"
    CACHE BOOL "Wendy CA verification" FORCE)
