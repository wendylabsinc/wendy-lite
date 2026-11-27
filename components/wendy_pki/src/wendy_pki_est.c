#include "wendy_pki_est.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    OUTER, SIGNED_OID, WRAPPER, SIGNED_SEQUENCE, VERSION, DIGESTS,
    DATA_SEQUENCE, DATA_OID, CERT_SET, CERT_HEADER, CERT_BODY, SIGNERS, COMPLETE
};

static const uint8_t signed_oid[] = {6, 9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 7, 2};
static const uint8_t data_oid[] = {6, 9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 7, 1};
static const uint8_t version[] = {2, 1, 1};
static const uint8_t empty_set[] = {0x31, 0};

/* Returns 1 when the length is complete, 0 for a partial header. */
static int read_header(struct pki_est_stream *s, uint8_t byte, size_t *length)
{
    if (s->header_size == sizeof s->header)
        return -1;
    s->header[s->header_size++] = byte;
    if (s->header_size < 2)
        return 0;
    unsigned code = s->header[1];
    if (code < 128) {
        *length = code;
        return 1;
    }
    unsigned octets = code & 127;
    if (!octets || octets > 3 || (s->header_size > 2 && !s->header[2]))
        return -1;
    if (s->header_size < octets + 2)
        return 0;
    *length = 0;
    for (unsigned i = 2; i < s->header_size; i++)
        *length = (*length << 8) | s->header[i];
    return *length >= 128 ? 1 : -1;
}

static int field(struct pki_est_stream *s, uint8_t byte,
                 const uint8_t *expected, size_t size, unsigned next)
{
    if (byte != expected[s->field_offset++])
        return -1;
    if (s->field_offset == size) {
        s->field_offset = 0;
        s->state = next;
    }
    return 0;
}

static int certificate_byte(struct pki_est_stream *s, uint8_t byte)
{
    s->current.der[s->cert_written++] = byte;
    if (s->cert_written < s->current.size)
        return 0;
    int keep = s->keep ? s->keep(s->current.der, s->current.size, s->context) : 1;
    if (keep < 0)
        return -1;
    if (keep) {
        s->stored += s->current.size;
        s->certs[s->count++] = s->current;
    } else {
        free(s->current.der);
    }
    s->current = (struct pki_est_cert){0};
    s->cert_written = 0;
    s->state = s->offset == s->certs_end ? SIGNERS : CERT_HEADER;
    return 0;
}

static int der_byte(struct pki_est_stream *s, uint8_t byte)
{
    if (++s->offset > PKI_EST_MAX_DER ||
        (s->outer_end && s->offset > s->outer_end))
        return -1;
    switch (s->state) {
    case SIGNED_OID:
        return field(s, byte, signed_oid, sizeof signed_oid, WRAPPER);
    case VERSION:
        return field(s, byte, version, sizeof version, DIGESTS);
    case DIGESTS:
        return field(s, byte, empty_set, sizeof empty_set, DATA_SEQUENCE);
    case DATA_OID:
        if (field(s, byte, data_oid, sizeof data_oid, CERT_SET))
            return -1;
        return s->state == CERT_SET && s->offset != s->data_end ? -1 : 0;
    case CERT_BODY:
        return certificate_byte(s, byte);
    case SIGNERS:
        if (field(s, byte, empty_set, sizeof empty_set, COMPLETE))
            return -1;
        return s->state == COMPLETE && s->offset != s->signed_end ? -1 : 0;
    case COMPLETE:
        return -1;
    default:
        break;
    }

    size_t length;
    int result = read_header(s, byte, &length);
    if (result <= 0)
        return result;
    unsigned tag = s->header[0], header_size = s->header_size;
    s->header_size = 0;
    if (length > PKI_EST_MAX_DER - s->offset)
        return -1;
    size_t end = s->offset + length;
    if (s->outer_end && end > s->outer_end)
        return -1;

    switch (s->state) {
    case OUTER:
        if (tag != 0x30 || !length)
            return -1;
        s->outer_end = end;
        s->state = SIGNED_OID;
        break;
    case WRAPPER:
        /* Older Wendy EST emits a direct SEQUENCE in ContentInfo. */
        if (end != s->outer_end)
            return -1;
        if (tag == 0xa0) {
            s->wrapper_end = end;
            s->state = SIGNED_SEQUENCE;
            break;
        }
        if (tag != 0x30)
            return -1;
        s->signed_end = end;
        s->state = VERSION;
        break;
    case SIGNED_SEQUENCE:
        if (tag != 0x30 || end != s->wrapper_end)
            return -1;
        s->signed_end = end;
        s->state = VERSION;
        break;
    case DATA_SEQUENCE:
        if (tag != 0x30 || length != sizeof data_oid)
            return -1;
        s->data_end = end;
        s->state = DATA_OID;
        break;
    case CERT_SET:
        if (tag != 0xa0 || !length || s->signed_end - end != sizeof empty_set)
            return -1;
        s->certs_end = end;
        s->state = CERT_HEADER;
        break;
    case CERT_HEADER:
        if (tag != 0x30 || !length || end > s->certs_end ||
            length + header_size > PKI_EST_MAX_CERT_SIZE ||
            length + header_size > PKI_EST_MAX_DER - s->stored ||
            s->seen++ == PKI_EST_MAX_CERTS)
            return -1;
        s->current.size = length + header_size;
        s->current.der = malloc(s->current.size);
        if (!s->current.der)
            return -1;
        memcpy(s->current.der, s->header, header_size);
        s->cert_written = header_size;
        s->state = CERT_BODY;
        break;
    default:
        return -1;
    }
    return 0;
}

static int base64_value(unsigned c)
{
    if (c >= 'A' && c <= 'Z') return (int)(c - 'A');
    if (c >= 'a' && c <= 'z') return (int)(c - 'a' + 26);
    if (c >= '0' && c <= '9') return (int)(c - '0' + 52);
    if (c == '+') return 62;
    if (c == '/') return 63;
    if (c == '=') return 64;
    return -1;
}

static int quartet(struct pki_est_stream *s)
{
    const uint8_t *v = s->base64;
    if (v[0] == 64 || v[1] == 64 ||
        (v[2] == 64 && (v[3] != 64 || (v[1] & 15))) ||
        (v[2] != 64 && v[3] == 64 && (v[2] & 3)))
        return -1;
    s->padded = v[3] == 64;
    s->base64_size = 0;
    if (der_byte(s, (uint8_t)((v[0] << 2) | (v[1] >> 4))))
        return -1;
    if (v[2] != 64 && der_byte(s, (uint8_t)((v[1] << 4) | (v[2] >> 2))))
        return -1;
    return v[3] != 64 && der_byte(s, (uint8_t)((v[2] << 6) | v[3])) ? -1 : 0;
}

int pki_est_feed(struct pki_est_stream *s, const uint8_t *bytes, size_t size)
{
    if (s->failed || size > PKI_EST_MAX_BODY - s->wire)
        return -1;
    s->wire += size;
    for (size_t i = 0; i < size; i++) {
        unsigned c = bytes[i];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
            continue;
        int value = base64_value(c);
        if (s->padded || value < 0) {
            s->failed = true;
            return -1;
        }
        s->base64[s->base64_size++] = (uint8_t)value;
        if (s->base64_size == 4 && quartet(s)) {
            s->failed = true;
            return -1;
        }
    }
    return 0;
}

bool pki_est_complete(const struct pki_est_stream *s)
{
    return !s->failed && s->state == COMPLETE && !s->base64_size &&
           s->offset == s->outer_end && s->count;
}

void pki_est_free(struct pki_est_stream *s)
{
    free(s->current.der);
    for (size_t i = 0; i < s->count; i++)
        free(s->certs[i].der);
    *s = (struct pki_est_stream){0};
}

int pki_est_url(char *url, size_t capacity, const char *configured, const char *csr,
                 const char *tenant, bool lite)
{
    const char *suffix = lite ? "?chain_algorithm=ECDSA_P256&full_chain=true" : "";
    int length;
    if (configured[0]) {
        if (strncmp(configured, "https://", 8) || strpbrk(configured, "# \t\r\n"))
            return -1;
        const char *query = strchr(configured, '?');
        length = snprintf(url, capacity, "%s%s%s", configured,
                          lite && query ? "&" : "", lite && query ? suffix + 1 : suffix);
    } else {
        static const struct { const char *prefix, *host; } hosted[] = {
            {"https://csr.pki.wendy.dev/v1/", "est.pki.wendy.dev"},
            {"https://csr.dev.pki.wendy.dev/v1/", "est.dev.pki.wendy.dev"},
            {"https://csr.pki.wendy.sh/v1/", "est.pki.wendy.sh"},
            {"https://csr.dev.pki.wendy.sh/v1/", "est.dev.pki.wendy.sh"},
        };
        const char *host = NULL;
        for (size_t i = 0; i < sizeof hosted / sizeof hosted[0]; i++) {
            size_t prefix = strlen(hosted[i].prefix);
            if (!strncmp(csr, hosted[i].prefix, prefix) && !strcmp(csr + prefix, tenant)) {
                host = hosted[i].host;
                break;
            }
        }
        if (!host)
            return -1;
        length = snprintf(url, capacity, "https://%s/.well-known/est/%s/cacerts%s",
                          host, tenant, suffix);
    }
    return length < 0 || (size_t)length >= capacity ? -1 : 0;
}
