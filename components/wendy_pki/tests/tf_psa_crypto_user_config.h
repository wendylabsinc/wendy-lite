#ifndef WENDY_TEST_TF_PSA_CRYPTO_USER_CONFIG_H
#define WENDY_TEST_TF_PSA_CRYPTO_USER_CONFIG_H

/* Match firmware for one test target: the ESP-IDF preset leaves mbedTLS date
 * checks out. This option must be set here, not in mbedtls_user_config.h. */
#undef MBEDTLS_HAVE_TIME_DATE

#endif
