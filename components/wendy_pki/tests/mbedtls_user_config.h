#ifndef WENDY_TEST_MBEDTLS_USER_CONFIG_H
#define WENDY_TEST_MBEDTLS_USER_CONFIG_H

/* Match firmware: ML-DSA-65 signatures, without hybrid ML-KEM exchange. */
#undef MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_GROUP_X25519MLKEM768

#endif
