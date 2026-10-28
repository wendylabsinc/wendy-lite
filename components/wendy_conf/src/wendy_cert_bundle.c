#include "wendy_cert_bundle.h"
#include <mbedtls/base64.h>
#include <string.h>

int wendy_cert_der_next(const uint8_t *data, size_t size, size_t *offset,
                        const uint8_t **der, size_t *bytes)
{
    if (!data || !offset || *offset > size || !der || !bytes) return -1;
    if (*offset == size) return 0;
    const uint8_t *p = data + *offset;
    size_t left = size - *offset, header = 2, length;
    if (left < 2 || p[0] != 0x30) return -1;
    length = p[1];
    if (length & 128U) {
        size_t octets = length & 127U;
        length = 0;
        if (!octets || octets > sizeof(size_t) || octets > left - 2 || !p[2]) return -1;
        header += octets;
        for (size_t i = 0; i < octets; i++) length = (length << 8) | p[2 + i];
        if (length < 128) return -1;
    }
    if (!length || length > left - header) return -1;
    *der = p;
    *bytes = header + length;
    *offset += *bytes;
    return 1;
}

static int whitespace(uint8_t c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static int convert(const uint8_t *data, size_t size, uint8_t *out,
                   size_t capacity, size_t *written)
{
    static const char begin[] = "-----BEGIN CERTIFICATE-----";
    static const char end[] = "-----END CERTIFICATE-----";
    if (!data || !size || size > WENDY_CERT_BUNDLE_MAX_BYTES || !written) return -1;
    size_t at = 0, total = 0;
    unsigned count = 0;
    while (at < size && whitespace(data[at])) at++;
    /* Import chooses one format for the complete bundle. */
    int pem = at < size && data[at] == '-';
    if (!pem) at = 0;
    while (at < size) {
        size_t bytes = 0;
        const uint8_t *part = NULL;
        if (++count > WENDY_CERT_BUNDLE_MAX_CERTS) return -1;
        if (pem) {
            if (size - at < sizeof begin - 1 ||
                memcmp(data + at, begin, sizeof begin - 1)) return -1;
            size_t body = at + sizeof begin - 1, tail = body;
            while (size - tail >= sizeof end - 1 &&
                   memcmp(data + tail, end, sizeof end - 1)) tail++;
            if (size - tail < sizeof end - 1) return -1;
            int result = mbedtls_base64_decode(NULL, 0, &bytes, data + body, tail - body);
            if (result != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL || !bytes) return -1;
            if (out) {
                if (total > capacity || bytes > capacity - total ||
                    mbedtls_base64_decode(out + total, capacity - total, &bytes,
                                          data + body, tail - body)) return -1;
                size_t offset = 0, extent;
                const uint8_t *der;
                if (wendy_cert_der_next(out + total, bytes, &offset, &der, &extent) != 1 ||
                    offset != bytes) return -1;
            }
            at = tail + sizeof end - 1;
            while (at < size && whitespace(data[at])) at++;
        } else {
            if (wendy_cert_der_next(data, size, &at, &part, &bytes) != 1) return -1;
            if (out) {
                if (total > capacity || bytes > capacity - total) return -1;
                memcpy(out + total, part, bytes);
            }
        }
        if (bytes > WENDY_CERT_BUNDLE_MAX_BYTES - total) return -1;
        total += bytes;
    }
    if (!count) return -1;
    *written = total;
    return 0;
}

int wendy_cert_bundle_measure(const uint8_t *data, size_t size, size_t *bytes)
{
    return convert(data, size, NULL, 0, bytes);
}

int wendy_cert_bundle_import(const uint8_t *data, size_t size, uint8_t *out,
                             size_t capacity, size_t *bytes)
{
    return out ? convert(data, size, out, capacity, bytes) : -1;
}
