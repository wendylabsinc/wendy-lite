#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#define PKI_EST_MAX_BODY (128U * 1024)
#define PKI_EST_MAX_CERTS 16
#define PKI_EST_MAX_CERT_SIZE (12U * 1024)
#define PKI_EST_MAX_DER (64U * 1024)

struct pki_est_cert {
    uint8_t *der;
    size_t size;
};

struct pki_est_stream {
    struct pki_est_cert certs[PKI_EST_MAX_CERTS];
    struct pki_est_cert current;
    size_t count, seen, stored, wire, offset;
    size_t outer_end, wrapper_end, signed_end, data_end, certs_end, cert_written;
    unsigned state, header_size, field_offset, base64_size;
    uint8_t header[5], base64[4];
    bool padded, failed;
    int (*keep)(const uint8_t *der, size_t size, void *context);
    void *context;
};

int pki_est_feed(struct pki_est_stream *stream, const uint8_t *bytes, size_t size);
bool pki_est_complete(const struct pki_est_stream *stream);
void pki_est_free(struct pki_est_stream *stream);

/* The authenticated, tenant-specific EST response supplies the CA hierarchy.
 * The classical twin already held by the board binds it to this enrollment. */
struct pki_est_classical_scope {
    uint8_t issuer[256];
    size_t issuer_size;
    char label[160];
};

int pki_est_lite_order(struct pki_est_stream *stream, const char *tenant,
                       const struct pki_est_cert *own, struct pki_est_classical_scope *scope);
int pki_est_keep_regular(const uint8_t *der, size_t size, void *context);
int pki_est_regular_pins(struct pki_est_stream *stream, const struct pki_est_cert *signed_lite,
                         const struct pki_est_classical_scope *scope, time_t now);

int pki_est_url(char *url, size_t capacity, const char *configured, const char *csr,
                 const char *tenant, bool lite);
