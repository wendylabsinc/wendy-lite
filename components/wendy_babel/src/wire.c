/* SPDX-License-Identifier: Apache-2.0
 * Ported from WendyOS go/babel/internal/wire; bounded, allocation-free codec.
 */
#include "wendy_babel.h"
#include <string.h>

static uint16_t u16(const uint8_t *p) { return (uint16_t)((unsigned)p[0] << 8 | p[1]); }
static uint64_t u64(const uint8_t *p)
{
    uint64_t v = 0;
    for (unsigned i = 0; i < 8; i++)
        v = v << 8 | p[i];
    return v;
}
static void put16(uint8_t *p, uint16_t v)
{
    p[0] = v >> 8;
    p[1] = v;
}
static void put64(uint8_t *p, uint64_t v)
{
    for (unsigned i = 0; i < 8; i++)
        p[7 - i] = (uint8_t)(v >> (8 * i));
}
bool wb_prefix_equal(const struct wb_prefix *a, const struct wb_prefix *b)
{
    return a->family == b->family && a->bits == b->bits && !memcmp(a->bytes, b->bytes, 16);
}
void wb_prefix_mask(struct wb_prefix *p)
{
    unsigned bits = p->bits;
    for (unsigned i = 0; i < 16; i++)
    {
        if (bits >= 8)
            bits -= 8;
        else
        {
            p->bytes[i] &= bits ? (uint8_t)(255u << (8 - bits)) : 0;
            bits = 0;
        }
    }
}
bool wb_prefix_valid(const struct wb_prefix *p)
{
    if ((p->family != 4 && p->family != 6) || p->bits > (p->family == 4 ? 32 : 128))
        return false;
    struct wb_prefix masked = *p;
    wb_prefix_mask(&masked);
    return !memcmp(p->bytes, masked.bytes, 16);
}
static bool subs(const uint8_t *p, size_t n)
{
    while (n)
    {
        unsigned t = *p++;
        n--;
        if (!t)
            continue;
        if (n < 1 || p[0] > n - 1 || (t & 128))
            return false;
        size_t take = 1 + p[0];
        p += take;
        n -= take;
    }
    return true;
}
static bool address(unsigned ae, const uint8_t *p, size_t n, uint8_t out[16], uint8_t *family,
                    size_t *used)
{
    memset(out, 0, 16);
    *family = 0;
    *used = 0;
    if (ae == 0)
        return true;
    if (ae == 1 && n >= 4)
    {
        memcpy(out, p, 4);
        *family = 4;
        *used = 4;
        return true;
    }
    if (ae == 2 && n >= 16)
    {
        memcpy(out, p, 16);
        *family = 6;
        *used = 16;
        return true;
    }
    if (ae == 3 && n >= 8)
    {
        out[0] = 0xfe;
        out[1] = 0x80;
        memcpy(out + 8, p, 8);
        *family = 6;
        *used = 8;
        return true;
    }
    return false;
}
static bool prefix(unsigned ae, unsigned bits, unsigned omitted, const uint8_t *p, size_t n,
                   const struct wb_prefix *previous, struct wb_prefix *out, size_t *used)
{
    if (ae < 1 || ae > 4 || bits > ((ae == 1 || ae == 4) ? 32u : 128u))
        return false;
    unsigned start = ae == 3 ? 8 : 0, bytes = (bits + 7) / 8;
    if (ae == 3 && (omitted || bits < 64))
        return false;
    if (bytes < start + omitted || bytes - start - omitted > n || (omitted && !previous->family))
        return false;
    memset(out, 0, sizeof *out);
    out->family = (ae == 1 || ae == 4) ? 4 : 6;
    out->bits = (uint8_t)bits;
    if (omitted)
        memcpy(out->bytes, previous->bytes, 16);
    if (ae == 3)
    {
        out->bytes[0] = 0xfe;
        out->bytes[1] = 0x80;
    }
    *used = bytes - start - omitted;
    memcpy(out->bytes + start + omitted, p, *used);
    wb_prefix_mask(out);
    return true;
}
int wb_decode(const void *data, size_t size, const uint8_t source[16],
              void (*visit)(void *, const struct wb_message *), void *ctx)
{
    const uint8_t *packet = data;
    if (!source || !packet || size < 4 || packet[0] != 42 || packet[1] != 2 ||
        u16(packet + 2) > size - 4)
        return WB_INVALID;
    size_t body = u16(packet + 2), pos = 4;
    /* Validate all outer TLV lengths before producing any state changes. */
    while (pos < 4 + body)
    {
        unsigned t = packet[pos++];
        if (!t)
            continue;
        if (pos >= 4 + body || packet[pos] > 4 + body - pos - 1)
            return WB_INVALID;
        pos += 1 + packet[pos];
    }
    struct wb_prefix previous[5] = {0};
    uint8_t hops[2][16] = {{0}}, hop_family[2] = {0, 6};
    memcpy(hops[1], source, 16);
    uint64_t router = 0;
    pos = 4;
    while (pos < 4 + body)
    {
        unsigned t = packet[pos++];
        if (!t)
            continue;
        size_t n = packet[pos++], used = 0, z = 0;
        const uint8_t *p = packet + pos;
        pos += n;
        struct wb_message m = {.type = (uint8_t)t};
        switch (t)
        {
        case WB_HELLO:
        case WB_ACK_REQUEST:
            if (n < 6)
                continue;
            used = 6;
            m.seqno = m.opaque = u16(p + 2);
            m.interval = u16(p + 4);
            m.unicast = (p[0] & 128) != 0;
            if (t == WB_ACK_REQUEST && !m.interval)
                continue;
            break;
        case WB_ACK:
            if (n < 2)
                continue;
            used = 2;
            m.opaque = u16(p);
            break;
        case WB_IHU:
        case WB_NEXT_HOP:
        {
            unsigned base = t == WB_IHU ? 6 : 2;
            if (n < base || !address(p[0], p + base, n - base, m.address, &m.address_family, &z) ||
                (t == WB_NEXT_HOP && !p[0]))
                continue;
            used = base + z;
            if (t == WB_NEXT_HOP)
            {
                unsigned f = m.address_family == 4 ? 0 : 1;
                memcpy(hops[f], m.address, 16);
                hop_family[f] = m.address_family;
            }
            else
            {
                m.metric = u16(p + 2);
                m.interval = u16(p + 4);
                if (!m.interval)
                    continue;
            }
            break;
        }
        case WB_ROUTER:
            if (n < 10)
                continue;
            used = 10;
            router = m.router = u64(p + 2);
            break;
        case WB_UPDATE:
        {
            if (n < 10)
                continue;
            unsigned ae = p[0];
            m.interval = u16(p + 4);
            m.seqno = u16(p + 6);
            m.metric = u16(p + 8);
            m.via6 = ae == 4;
            if (!ae)
            {
                if (p[2] || p[3] || m.metric != WB_INFINITY)
                    continue;
                used = 10;
                m.wildcard = true;
            }
            else
            {
                if (ae > 4 || !prefix(ae, p[2], p[3], p + 10, n - 10, &previous[ae], &m.prefix, &z))
                    continue;
                used = 10 + z;
                if ((p[1] & 128) && ae != 3)
                    previous[ae] = m.prefix;
                if (p[1] & 64)
                    router = m.prefix.family == 4
                                 ? (uint64_t)m.prefix.bytes[0] << 24 |
                                       (uint64_t)m.prefix.bytes[1] << 16 |
                                       (uint64_t)m.prefix.bytes[2] << 8 | m.prefix.bytes[3]
                                 : u64(m.prefix.bytes + 8);
                m.router = router;
                unsigned f = ae == 1 ? 0 : 1;
                memcpy(m.address, hops[f], 16);
                m.address_family = hop_family[f];
                if (m.metric != WB_INFINITY &&
                    (!router || router == UINT64_MAX || !m.address_family))
                    continue;
            }
            if (!m.interval)
                continue;
            break;
        }
        case WB_REQUEST:
        case WB_SEQ_REQUEST:
        {
            unsigned base = t == WB_REQUEST ? 2 : 14;
            if (n < base)
                continue;
            if (!p[0])
            {
                if (t != WB_REQUEST || p[1])
                    continue;
                used = base;
                m.wildcard = true;
            }
            else
            {
                struct wb_prefix none = {0};
                if (!prefix(p[0], p[1], 0, p + base, n - base, &none, &m.prefix, &z))
                    continue;
                used = base + z;
            }
            if (t == WB_SEQ_REQUEST)
            {
                m.seqno = u16(p + 2);
                m.hops = p[4];
                m.router = u64(p + 6);
                if (!m.hops || !m.router || m.router == UINT64_MAX)
                    continue;
            }
            break;
        }
        default:
            continue;
        }
        if (!subs(p + used, n - used))
            continue;
        if (t != WB_ROUTER && t != WB_NEXT_HOP && visit)
            visit(ctx, &m);
    }
    return WB_OK;
}
size_t wb_encode(const struct wb_message *m, uint8_t *out, size_t cap)
{
    if (!m || !out ||
        ((m->type == WB_UPDATE || m->type == WB_REQUEST || m->type == WB_SEQ_REQUEST) &&
         !m->wildcard && !wb_prefix_valid(&m->prefix)) ||
        (m->address_family && m->address_family != 4 && m->address_family != 6))
        return 0;
    uint8_t p[64] = {0};
    size_t n = 0;
    switch (m->type)
    {
    case WB_HELLO:
    case WB_ACK_REQUEST:
        n = 8;
        p[0] = m->type;
        p[1] = 6;
        if (m->unicast && m->type == WB_HELLO)
            p[2] = 128;
        put16(p + 4, m->type == WB_ACK_REQUEST ? m->opaque : m->seqno);
        put16(p + 6, m->interval);
        break;
    case WB_ACK:
        n = 4;
        p[0] = WB_ACK;
        p[1] = 2;
        put16(p + 2, m->opaque);
        break;
    case WB_IHU:
        n = 8;
        p[0] = WB_IHU;
        p[1] = 6;
        put16(p + 4, m->metric);
        put16(p + 6, m->interval);
        if (m->address_family)
        {
            unsigned bytes = m->address_family == 4 ? 4 : 16;
            p[2] = m->address_family == 4 ? 1 : 2;
            memcpy(p + n, m->address, bytes);
            n += bytes;
            p[1] = (uint8_t)(n - 2);
        }
        break;
    case WB_UPDATE:
    {
        if (m->metric != WB_INFINITY)
        {
            p[0] = WB_ROUTER;
            p[1] = 10;
            put64(p + 4, m->router);
            n = 12;
            if (m->address_family)
            {
                unsigned bytes = m->address_family == 4 ? 4 : 16;
                p[n] = WB_NEXT_HOP;
                p[n + 1] = (uint8_t)(bytes + 2);
                p[n + 2] = m->address_family == 4 ? 1 : 2;
                memcpy(p + n + 4, m->address, bytes);
                n += bytes + 4;
            }
        }
        size_t at = n;
        p[n] = WB_UPDATE;
        p[n + 1] = 10;
        n += 12;
        put16(p + at + 6, m->interval);
        put16(p + at + 8, m->seqno);
        put16(p + at + 10, m->metric);
        if (!m->wildcard)
        {
            unsigned bytes = (m->prefix.bits + 7) / 8;
            p[at + 2] = m->prefix.family == 4 ? (m->via6 ? 4 : 1) : 2;
            p[at + 4] = m->prefix.bits;
            memcpy(p + n, m->prefix.bytes, bytes);
            n += bytes;
            p[at + 1] += (uint8_t)bytes;
        }
        break;
    }
    case WB_REQUEST:
    case WB_SEQ_REQUEST:
    {
        unsigned base = m->type == WB_REQUEST ? 2 : 14;
        p[0] = m->type;
        p[1] = (uint8_t)base;
        n = base + 2;
        if (!m->wildcard)
        {
            unsigned bytes = (m->prefix.bits + 7) / 8;
            p[2] = m->prefix.family == 4 ? 1 : 2;
            p[3] = m->prefix.bits;
            memcpy(p + n, m->prefix.bytes, bytes);
            n += bytes;
            p[1] += (uint8_t)bytes;
        }
        if (m->type == WB_SEQ_REQUEST)
        {
            put16(p + 4, m->seqno);
            p[6] = m->hops;
            put64(p + 8, m->router);
        }
        break;
    }
    default:
        return 0;
    }
    if (n > cap)
        return 0;
    memcpy(out, p, n);
    return n;
}
