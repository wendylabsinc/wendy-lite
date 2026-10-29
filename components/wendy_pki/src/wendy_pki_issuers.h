#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
/* Auxiliary offer understood by WendyOS. Never a selected application ALPN. */
#define PKI_ISSUER_HINT_SIZE 256
#define PKI_ISSUER_CHAIN_MAX 8
#define PKI_ISSUER_FINGERPRINT_SIZE 16
struct mbedtls_x509_crt;
struct pki_issuer_state {
    char hint[PKI_ISSUER_HINT_SIZE];
    const char *application;
    const char *protocols[PKI_ISSUER_CHAIN_MAX+5];
    size_t protocol_lengths[PKI_ISSUER_CHAIN_MAX+5];
    uint8_t chain[PKI_ISSUER_CHAIN_MAX][16];
    uint8_t available[24][16];
    unsigned chain_count,available_count,omit_mask;
    size_t hint_length;
    unsigned char cached_hint[3][17+PKI_ISSUER_CHAIN_MAX*16];
    unsigned peer_presented_certificates;
    size_t peer_der_bytes;
    bool omit;
    unsigned known_count;
    struct mbedtls_x509_crt *known[16], *owned[16];
    uint8_t *der[16];
    void *cached_context;
    void (*release_cached)(void *);
};
/* Inspect complete, already Mbed TLS-validated TLS1.3 handshake messages.
 * An unavailable/unrecognized layout simply leaves the ordinary full chain. */
bool pki_client_hello_offers(const uint8_t *message,size_t size,const char *protocol);
unsigned pki_certificate_message_count(const uint8_t *message,size_t size);

/* Binary per-CA availability. Prefix names are real protocol variants; the
 * selected prefix explicitly acknowledges which client CAs the server has. */
int pki_issuer_protocols(struct pki_issuer_state *,const char *application);
size_t pki_issuer_select(struct pki_issuer_state *,const uint8_t *,size_t);
bool pki_issuer_peer_has(const uint8_t *,size_t,const char *,const uint8_t[16]);
bool pki_issuer_ack_has(const uint8_t *,size_t,const char *,const uint8_t[16]);

bool pki_certificate_message_last(const uint8_t *,size_t,const uint8_t **,size_t *);

size_t pki_certificate_message_der_bytes(const uint8_t *,size_t);
