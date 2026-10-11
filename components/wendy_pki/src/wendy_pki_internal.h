#pragma once
#include "wendy_pki.h"
#include "wendy_conf.h"
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
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
    mbedtls_ssl_config config;
    mbedtls_ssl_context ssl;
    mbedtls_x509_crt roots, certificate;
    mbedtls_pk_context key;
    int fd;
    uint8_t device_hash[32], operator_hash[32];
    int64_t relay_expires_us;
};
int pki_tls_connect(const char *host, unsigned port, const uint8_t *key, size_t key_size,
                    const char *cert, struct wendy_conf_span roots, wendy_pki_connection **out);
int pki_http_post(const char *url, const char *type, const char *token, const void *body,
                  size_t body_size, const uint8_t *key, size_t key_size, const char *cert,
                  struct wendy_conf_span roots, uint8_t **response, size_t *response_size);

int pki_tls_accept(int fd, const uint8_t *key, size_t key_size, const char *cert,
                   struct wendy_conf_span roots, const char *tenant, wendy_pki_connection **out, int64_t deadline);

int pki_relay_grant(wendy_pki_connection *, const struct wendy_lite_trust *, int64_t deadline);

int wendy_pki_rng(void *context, unsigned char *out, size_t size);
