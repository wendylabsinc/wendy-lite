#ifndef WENDY_TEST_MBEDTLS_USER_CONFIG_H
#define WENDY_TEST_MBEDTLS_USER_CONFIG_H

/* Match firmware: ML-DSA-65 signatures, without hybrid ML-KEM exchange. */
#undef MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_GROUP_X25519MLKEM768
#define MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH
/* Match non-PSRAM firmware: receive full records while sending smaller ones. */
#define MBEDTLS_SSL_IN_CONTENT_LEN 16384
#define MBEDTLS_SSL_OUT_CONTENT_LEN 2048

#endif
