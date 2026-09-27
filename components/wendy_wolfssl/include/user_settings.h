#ifndef WENDY_WOLFSSL_SETTINGS_H
#define WENDY_WOLFSSL_SETTINGS_H
#ifdef ESP_PLATFORM
#include "sdkconfig.h"
#include <arpa/inet.h>
#include <sys/socket.h>
/* Use ESP-IDF POSIX locks and explicit socket/RNG adapters. */
#define WOLFSSL_NO_SOCK
#define WOLFSSL_USER_IO
#define CUSTOM_RAND_GENERATE_BLOCK wendy_pki_random
#include <stddef.h>
int wendy_pki_random(unsigned char *out, unsigned int size);
#else
#include <stdlib.h>
#include <unistd.h>
#include <sys/random.h>
static inline int wendy_pki_host_random(unsigned char *p, unsigned int n)
{
    while (n)
    {
        unsigned int block = n > 256 ? 256 : n;
        if (getentropy(p, block))
            return -1;
        p += block;
        n -= block;
    }
    return 0;
}
#define CUSTOM_RAND_GENERATE_BLOCK wendy_pki_host_random
#endif
#define WOLFSSL_SMALL_STACK
#define WOLFSSL_SP_MATH_ALL
#define WOLFSSL_SP_SMALL
#define WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_HAVE_SP_RSA
#define NO_ASM
#define NO_FILESYSTEM
#define NO_WRITEV
#define NO_OLD_TLS
#define NO_DSA
#define NO_DH
#define NO_RC4
#define NO_DES3
#define NO_MD4
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING
#define HAVE_ECC
#define HAVE_AESGCM
#define HAVE_HKDF
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define HAVE_SNI
#define HAVE_EXTENDED_MASTER
#define WOLFSSL_TLS13
#define WC_RSA_PSS
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE128
#define WOLFSSL_SHAKE256
#define HAVE_DILITHIUM
#define WOLFSSL_WC_DILITHIUM
#define WOLFSSL_DILITHIUM_LEVEL2
#define WOLFSSL_DILITHIUM_LEVEL3
#define WOLFSSL_DILITHIUM_LEVEL5
#define OPENSSL_EXTRA
#define OPENSSL_ALL
#define WOLFSSL_ALT_CERT_CHAINS
#define WOLFSSL_CERT_GEN
#define WOLFSSL_CERT_REQ
#define WOLFSSL_CERT_EXT
#define WOLFSSL_BASE64_ENCODE
#define WOLFSSL_ASN_TEMPLATE
#define WOLFSSL_ASN_ANY
#define WOLFSSL_NO_TLS12
#define WC_CTC_MAX_ALT_SIZE 512
#endif
