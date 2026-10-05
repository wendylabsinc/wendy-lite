#pragma once
#include "wendy_pki.h"
#include "wendy_conf.h"
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/settings.h>
#define PKI_MAX_RESPONSE 65536
extern const uint8_t wendy_pki_device_roots_start[] asm("_binary_wendy_pki_device_roots_start");
extern const uint8_t wendy_pki_device_roots_end[] asm("_binary_wendy_pki_device_roots_end");
extern const uint8_t wendy_pki_tsa_roots_start[] asm("_binary_wendy_pki_tsa_roots_start");
extern const uint8_t wendy_pki_tsa_roots_end[] asm("_binary_wendy_pki_tsa_roots_end");
extern const uint8_t wendy_pki_https_roots_start[] asm("_binary_wendy_pki_https_roots_start");
extern const uint8_t wendy_pki_https_roots_end[] asm("_binary_wendy_pki_https_roots_end");
#define ROOT_SIZE(kind) (wendy_pki_##kind##_roots_end - wendy_pki_##kind##_roots_start - 1)
struct wendy_pki_connection
{
    WOLFSSL_CTX *ctx;
    WOLFSSL *ssl;
    int fd;
};
int pki_tls_connect(const char *host, unsigned port, const uint8_t *key, size_t key_size,
                    const char *cert, struct wendy_conf_span roots, wendy_pki_connection **out);
int pki_http_post(const char *url, const char *type, const char *token, const void *body,
                  size_t body_size, const uint8_t *key, size_t key_size, const char *cert,
                  struct wendy_conf_span roots, uint8_t **response, size_t *response_size);
