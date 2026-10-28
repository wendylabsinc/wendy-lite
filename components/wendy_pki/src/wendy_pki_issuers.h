#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
/* Auxiliary offer understood by WendyOS. Never a selected application ALPN. */
#define PKI_ISSUER_HINT_PREFIX "wendy-net-issuers/"
#define PKI_ISSUER_HINT_SIZE 41
struct pki_issuer_state {
    char hint[PKI_ISSUER_HINT_SIZE];
    const char *protocols[3];
    uint8_t own_issuer_identity[32];
    unsigned peer_presented_certificates;
    bool omit;
};
/* Caller supplies only independently verified, exactly pinned issuer hashes. */
int pki_issuer_hint(const uint8_t hashes[][32],size_t count,char output[PKI_ISSUER_HINT_SIZE]);
/* Inspect complete, already Mbed TLS-validated TLS1.3 handshake messages.
 * An unavailable/unrecognized layout simply leaves the ordinary full chain. */
bool pki_client_hello_offers(const uint8_t *message,size_t size,const char *protocol);
unsigned pki_certificate_message_count(const uint8_t *message,size_t size);
