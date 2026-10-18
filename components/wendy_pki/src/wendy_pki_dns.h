#pragma once
#include <stddef.h>
#include <stdint.h>
#include <string.h>
/* A bounded A lookup for independent uplink probes. Its answer supplies only
 * a dial address; Cloud TLS still verifies the original hostname and CA path. */
static inline unsigned pki_dns_u16(const uint8_t* p) { return (unsigned)p[0] * 256 + p[1]; }
static inline size_t pki_dns_query(uint8_t out[272], const char* host, uint16_t id)
{
    if (!host || !host[0] || strlen(host) > 253) return 0;
    memset(out, 0, 12); out[0] = id >> 8; out[1] = id; out[2] = 1; out[5] = 1;
    size_t pos = 12;
    while (*host) {
        const char* dot = strchr(host, '.');
        size_t n = dot ? (size_t)(dot - host) : strlen(host);
        if (!n || n > 63) return 0;
        out[pos++] = n; memcpy(out + pos, host, n); pos += n;
        host += n;
        if (*host == '.') host++;
    }
    out[pos++] = 0; out[pos++] = 0; out[pos++] = 1; out[pos++] = 0; out[pos++] = 1;
    return pos;
}
static inline int pki_dns_name(const uint8_t* p, size_t n, size_t* offset)
{
    size_t pos = *offset;
    unsigned length = 0;
    while (pos < n) {
        unsigned count = p[pos++];
        if (!count) { *offset = pos; return 0; }
        if ((count & 0xc0) == 0xc0) {
            if (pos >= n || (((count & 63) << 8) | p[pos]) >= n) return -1;
            *offset = pos + 1; return 0;
        }
        if (count > 63 || count > n - pos || (length += count + 1) > 255) return -1;
        pos += count;
    }
    return -1;
}
static inline int pki_dns_answer(const uint8_t* query, size_t qn,
    const uint8_t* reply, size_t n, uint8_t address[4])
{
    if (!query || qn < 17 || !reply || n < qn || n > 1024
        || memcmp(query, reply, 2) || (reply[2] & 0xfa) != 0x80 || (reply[3] & 0x0f)
        || pki_dns_u16(reply + 4) != 1 || memcmp(query + 12, reply + 12, qn - 12)) return -1;
    size_t pos = qn;
    unsigned answers = pki_dns_u16(reply + 6);
    if (answers > 64) return -1;
    for (unsigned i = 0; i < answers; i++) {
        if (pki_dns_name(reply, n, &pos) || n - pos < 10) return -1;
        unsigned type = pki_dns_u16(reply + pos), cls = pki_dns_u16(reply + pos + 2);
        unsigned size = pki_dns_u16(reply + pos + 8); pos += 10;
        if (size > n - pos) return -1;
        if (type == 1 && cls == 1 && size == 4) { memcpy(address, reply + pos, 4); return 0; }
        pos += size;
    }
    return -1;
}
