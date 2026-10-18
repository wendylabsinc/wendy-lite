#include "wendy_mesh_protocol.h"
#include <inttypes.h>
#ifdef ESP_PLATFORM
#include "lwip/sockets.h"
#else
#include <arpa/inet.h>
#endif
#include <limits.h>
#include <stdio.h>
#include <string.h>

uint16_t wm_get16(const uint8_t* p)
{
    return (uint16_t)((unsigned)p[0] << 8 | p[1]);
}
uint32_t wm_get32(const uint8_t* p)
{
    return (uint32_t)wm_get16(p) << 16 | wm_get16(p + 2);
}
void wm_put16(uint8_t* p, uint16_t v)
{
    p[0] = v >> 8;
    p[1] = v;
}
void wm_put32(uint8_t* p, uint32_t v)
{
    wm_put16(p, v >> 16);
    wm_put16(p + 2, v);
}
static int hex(char c)
{
    return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
}
int wm_uuid_parse(const char* s, uint8_t out[16])
{
    if (!s || strlen(s) != 36)
        return -1;
    unsigned n = 0;
    for (unsigned i = 0; i < 36;)
    {
        if (i == 8 || i == 13 || i == 18 || i == 23)
        {
            if (s[i++] != '-')
                return -1;
            continue;
        }
        int a = hex(s[i++]), b = hex(s[i++]);
        if (a < 0 || b < 0)
            return -1;
        out[n++] = (uint8_t)(a * 16 + b);
    }
    static const uint8_t zero[16];
    return memcmp(out, zero, 16) ? 0 : -1;
}
void wm_uuid_format(const uint8_t u[16], char out[37])
{
    snprintf(out, 37, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", u[0],
        u[1], u[2], u[3], u[4], u[5], u[6], u[7], u[8], u[9], u[10], u[11], u[12], u[13], u[14],
        u[15]);
}
void wm_address(const uint8_t u[16], uint8_t out[16])
{
    static const uint8_t prefix[] = { 0xfd, 0x45, 0xb8, 0x91, 0x56, 0x7f };
    memcpy(out, prefix, 6);
    memcpy(out + 6, u + 6, 10);
}
void wm_prefix(const uint8_t u[16], char out[48])
{
    uint8_t a[16];
    wm_address(u, a);
    snprintf(out, 48, "fd45:b891:567f:%x:%x:%x:%x:%x/128", wm_get16(a + 6), wm_get16(a + 8),
        wm_get16(a + 10), wm_get16(a + 12), wm_get16(a + 14));
}
int wm_principal(const char* tenant, const char* device, char out[106])
{
    uint8_t u[16];
    if (wm_uuid_parse(tenant, u) || wm_uuid_parse(device, u))
        return -1;
    int n = snprintf(out, 106, "spiffe://wendy.sh/tenant/%s/device/%s", tenant, device);
    return n == 105 ? n : -1;
}
int wm_principal_device(const char* s, const char* tenant, uint8_t device[16])
{
    char expected[106];
    if (!s || strlen(s) != 105 || wm_uuid_parse(s + 69, device)
        || wm_principal(tenant, s + 69, expected) < 0)
        return -1;
    return strcmp(s, expected) ? -1 : 0;
}

static void space(struct wm_json* d, size_t* p)
{
    while (*p < d->size && strchr(" \t\r\n", d->text[*p]))
        ++*p;
}
static int value(struct wm_json* d, size_t* p, unsigned depth)
{
    space(d, p);
    if (*p >= d->size || depth > 8 || d->count == WM_TOKENS)
        return -1;
    unsigned index = d->count++;
    struct wm_token* t = &d->tokens[index];
    t->start = *p;
    t->type = d->text[*p];
    char c = d->text[(*p)++];
    if (c == '{' || c == '[')
    {
        char end = c == '{' ? '}' : ']';
        space(d, p);
        if (*p < d->size && d->text[*p] != end)
            for (;;)
            {
                if (c == '{')
                {
                    space(d, p);
                    if (*p >= d->size || d->text[*p] != '"')
                        return -1;
                    int key = value(d, p, depth + 1);
                    if (key < 0)
                        return -1;
                    /* All keys are ASCII and unescaped, so duplicate detection is exact. */
                    struct wm_token* k = &d->tokens[key];
                    if (memchr(d->text + k->start + 1, '\\', k->end - k->start - 2))
                        return -1;
                    for (unsigned old = index + 1; old < (unsigned)key;)
                    {
                        struct wm_token* o = &d->tokens[old];
                        if (o->end - o->start == k->end - k->start
                            && !memcmp(d->text + o->start, d->text + k->start, k->end - k->start))
                            return -1;
                        old = d->tokens[old + 1].next;
                    }
                    space(d, p);
                    if (*p >= d->size || d->text[(*p)++] != ':')
                        return -1;
                }
                if (value(d, p, depth + 1) < 0)
                    return -1;
                space(d, p);
                if (*p >= d->size)
                    return -1;
                if (d->text[*p] == end)
                    break;
                if (d->text[(*p)++] != ',')
                    return -1;
            }
        if (*p >= d->size || d->text[(*p)++] != end)
            return -1;
    }
    else if (c == '"')
    {
        bool ended = false;
        while (*p < d->size)
        {
            unsigned char x = d->text[(*p)++];
            if (x == '"')
            {
                ended = true;
                break;
            }
            if (x < 32)
                return -1;
            if (x == '\\')
            {
                if (*p >= d->size)
                    return -1;
                char e = d->text[(*p)++];
                if (e == 'u')
                {
                    for (int i = 0; i < 4; i++)
                    {
                        if (*p >= d->size)
                            return -1;
                        char h = d->text[(*p)++];
                        if (hex(h) < 0 && !(h >= 'A' && h <= 'F'))
                            return -1;
                    }
                }
                else if (!strchr("\"\\/bfnrt", e))
                    return -1;
            }
        }
        if (!ended)
            return -1;
    }
    else if (c == 't' || c == 'f' || c == 'n')
    {
        const char* literal = c == 't' ? "true" : c == 'f' ? "false" : "null";
        size_t n = strlen(literal);
        if (t->start + n > d->size || memcmp(d->text + t->start, literal, n))
            return -1;
        *p = t->start + n;
    }
    else
    {
        *p = t->start;
        if (d->text[*p] == '-')
            ++*p;
        if (*p >= d->size || d->text[*p] < '0' || d->text[*p] > '9')
            return -1;
        if (d->text[(*p)++] != '0')
            while (*p < d->size && d->text[*p] >= '0' && d->text[*p] <= '9')
                ++*p;
        /* The protocol has no floating-point fields. Reject fractions and exponents. */
        t->type = '0';
    }
    t->end = *p;
    t->next = d->count;
    return (int)index;
}
int wm_json_parse(struct wm_json* d, const void* data, size_t size)
{
    if (!d || !data || !size || size > WENDY_MESH_CONTROL_MAX || memchr(data, 0, size))
        return -1;
    memset(d, 0, sizeof *d);
    d->text = data;
    d->size = size;
    size_t p = 0;
    if (value(d, &p, 0) < 0)
        return -1;
    space(d, &p);
    return p == size ? 0 : -1;
}
bool wm_json_equal(const struct wm_json* d, int token, const char* s)
{
    if (token < 0 || (unsigned)token >= d->count)
        return false;
    const struct wm_token* t = &d->tokens[token];
    size_t n = strlen(s);
    return t->type == '"' && t->end - t->start == n + 2 && !memcmp(d->text + t->start + 1, s, n);
}
int wm_json_member(const struct wm_json* d, unsigned obj, const char* key)
{
    if (obj >= d->count || d->tokens[obj].type != '{')
        return -1;
    for (unsigned i = obj + 1; i < d->tokens[obj].next; i = d->tokens[i + 1].next)
        if (wm_json_equal(d, i, key))
            return (int)i + 1;
    return -1;
}
bool wm_json_fields(const struct wm_json* d, unsigned obj, const char* const* fields)
{
    if (obj >= d->count || d->tokens[obj].type != '{')
        return false;
    for (unsigned i = obj + 1; i < d->tokens[obj].next; i = d->tokens[i + 1].next)
    {
        bool found = false;
        for (unsigned j = 0; fields[j]; j++)
            if (wm_json_equal(d, i, fields[j]))
                found = true;
        if (!found)
            return false;
    }
    return true;
}
int wm_json_string(const struct wm_json* d, int token, char* out, size_t capacity)
{
    if (token < 0 || (unsigned)token >= d->count || d->tokens[token].type != '"')
        return -1;
    const struct wm_token* t = &d->tokens[token];
    size_t n = t->end - t->start - 2;
    if (n >= capacity || memchr(d->text + t->start + 1, '\\', n))
        return -1;
    memcpy(out, d->text + t->start + 1, n);
    out[n] = 0;
    return (int)n;
}
int wm_json_u64(const struct wm_json* d, int token, uint64_t* out)
{
    if (token < 0 || (unsigned)token >= d->count || d->tokens[token].type != '0')
        return -1;
    uint64_t n = 0;
    const struct wm_token* t = &d->tokens[token];
    for (size_t p = t->start; p < t->end; p++)
    {
        unsigned x = (unsigned)(d->text[p] - '0');
        if (x > 9 || n > (UINT64_MAX - x) / 10)
            return -1;
        n = n * 10 + x;
    }
    *out = n;
    return 0;
}
static int number(const struct wm_json* d, unsigned obj, const char* key, uint64_t* out)
{
    return wm_json_u64(d, wm_json_member(d, obj, key), out);
}
int wm_manifest_write(const struct wm_manifest* m, char* out, size_t cap)
{
    if (!m || !m->revision || !m->router_id || m->router_id == UINT64_MAX || m->issued <= 0
        || m->expires <= m->issued || m->expires - m->issued > 120000 || !m->agent_port)
        return -1;
    char id[37], prefix[48];
    wm_uuid_format(m->device, id);
    wm_prefix(m->device, prefix);
    int n = snprintf(out, cap,
        "{\"version\":3,\"device\":\"%s\",\"revision\":%" PRIu64 ",\"Issued\":%" PRId64
        ",\"Expires\":%" PRId64 ",\"name\":\"wendy-lite-%.8s\",\"agentPort\":%u,%s\"route\":{"
        "\"prefix\":\"%s\",\"routerId\":%" PRIu64 ",\"seqno\":%u}}",
        id, m->revision, m->issued, m->expires, id, m->agent_port,
        m->withdraw ? "\"withdraw\":true," : "", prefix, m->router_id, m->seqno);
    return n < 0 || (size_t)n >= cap ? -1 : n;
}
int wm_manifest_parse(const struct wm_json* d, unsigned body, struct wm_manifest* m)
{
    static const char* const fields[] = { "version", "device", "revision", "Issued", "Expires",
        "name", "agentPort", "withdraw", "route", NULL };
    static const char* const route_fields[] = { "prefix", "routerId", "seqno", NULL };
    memset(m, 0, sizeof *m);
    uint64_t version, issued, expires, port, seq;
    char id[37], prefix[48], actual[48];
    int route = wm_json_member(d, body, "route"), withdraw = wm_json_member(d, body, "withdraw"),
        name = wm_json_member(d, body, "name");
    if (!wm_json_fields(d, body, fields) || route < 0 || !wm_json_fields(d, route, route_fields)
        || number(d, body, "version", &version) || version != 3
        || number(d, body, "revision", &m->revision) || !m->revision
        || number(d, body, "Issued", &issued) || issued == 0 || issued > INT64_MAX
        || number(d, body, "Expires", &expires) || expires > INT64_MAX || expires <= issued
        || expires - issued > 120000 || number(d, body, "agentPort", &port) || port > 65535
        || wm_json_string(d, wm_json_member(d, body, "device"), id, sizeof id) < 0
        || wm_uuid_parse(id, m->device)
        || wm_json_string(d, wm_json_member(d, route, "prefix"), actual, sizeof actual) < 0
        || number(d, route, "routerId", &m->router_id) || !m->router_id
        || m->router_id == UINT64_MAX || number(d, route, "seqno", &seq) || seq > 65535 || name < 0
        || d->tokens[name].type != '"' || d->tokens[name].end - d->tokens[name].start > 1532)
        return -1;
    wm_prefix(m->device, prefix);
    /* IPv6 text may be compressed by Go; address comparison is performed by
     * the crypto/runtime caller after parsing. Own emitted text is canonical. */
    if (strcmp(prefix, actual))
    {
        /* Accept only the equivalent /128. inet_pton is provided by lwIP and host libc. */
        uint8_t address[16], expected[16];
        size_t n = strlen(actual);
        if (n < 5 || strcmp(actual + n - 4, "/128"))
            return -1;
        actual[n - 4] = 0;
        wm_address(m->device, expected);
        if (inet_pton(AF_INET6, actual, address) != 1 || memcmp(address, expected, 16))
            return -1;
    }
    if (withdraw >= 0)
    {
        char t = d->tokens[withdraw].type;
        if (t != 't' && t != 'f')
            return -1;
        m->withdraw = t == 't';
    }
    if (!m->withdraw && !port)
        return -1;
    m->issued = issued;
    m->expires = expires;
    m->seqno = seq;
    m->agent_port = port;
    return 0;
}
int wm_hello_write(const char* device, const char* peer, char* out, size_t capacity)
{
    uint8_t u[16];
    if (wm_uuid_parse(device, u) || wm_uuid_parse(peer, u) || !strcmp(device, peer))
        return -1;
    int n = snprintf(out, capacity,
        "{\"kind\":\"hello\",\"hello\":{\"version\":3,\"device\":\"%s\",\"peer\":\"%s\",\"mtu\":"
        "1320,\"datagram\":1100}}",
        device, peer);
    return n < 0 || (size_t)n >= capacity ? -1 : n;
}
int wm_hello_check(const void* data, size_t size, const char* device, const char* peer)
{
    struct wm_json d;
    static const char* const fields[] = { "kind", "hello", NULL };
    static const char* const hello[] = { "version", "device", "peer", "mtu", "datagram", NULL };
    if (wm_json_parse(&d, data, size) || !wm_json_fields(&d, 0, fields)
        || !wm_json_equal(&d, wm_json_member(&d, 0, "kind"), "hello"))
        return -1;
    int h = wm_json_member(&d, 0, "hello");
    uint64_t v, mtu, datagram;
    return h >= 0 && wm_json_fields(&d, h, hello) && !number(&d, h, "version", &v) && v == 3
            && !number(&d, h, "mtu", &mtu) && mtu == 1320 && !number(&d, h, "datagram", &datagram)
            && datagram == 1100 && wm_json_equal(&d, wm_json_member(&d, h, "device"), peer)
            && wm_json_equal(&d, wm_json_member(&d, h, "peer"), device)
        ? 0
        : -1;
}
size_t wm_babel_announce(
    uint8_t out[64], const uint8_t device[16], uint64_t rid, uint16_t seq, uint16_t hello)
{
    if (!rid || rid == UINT64_MAX)
        return 0;
    memset(out, 0, 64);
    out[0] = 42;
    out[1] = 2;
    wm_put16(out + 2, 56);
    out[4] = 4;
    out[5] = 6;
    out[6] = 128;
    wm_put16(out + 8, hello);
    wm_put16(out + 10, 400);
    out[12] = 5;
    out[13] = 6;
    wm_put16(out + 16, 96);
    wm_put16(out + 18, 1200);
    out[20] = 6;
    out[21] = 10;
    wm_put32(out + 24, rid >> 32);
    wm_put32(out + 28, rid);
    out[32] = 8;
    out[33] = 26;
    out[34] = 2;
    out[36] = 128;
    wm_put16(out + 38, 1200);
    wm_put16(out + 40, seq);
    wm_address(device, out + 44);
    return 60;
}
bool wm_ip_valid(const uint8_t* p, size_t n)
{
    return p && n >= 40 && n <= WENDY_MESH_MTU && (p[0] >> 4) == 6 && wm_get16(p + 4) == n - 40;
}
int wm_assemble(struct wm_assembler* s, const uint8_t* p, size_t n, int64_t now)
{
    if (n < 10 || n > WENDY_MESH_DATAGRAM || p[0] != 1)
        return -1;
    uint32_t id = wm_get32(p + 1);
    uint16_t total = wm_get16(p + 5), offset = wm_get16(p + 7);
    size_t count = n - 9;
    if (total < 40 || total > WENDY_MESH_MTU || (offset != 0 && offset != 1091) || offset >= total
        || count != (total - offset < 1091 ? total - offset : 1091))
        return -1;
    if (!s->parts || now >= s->deadline_us || s->id != id)
    {
        memset(s, 0, sizeof *s);
        s->id = id;
        s->total = total;
        s->deadline_us = now + INT64_C(2000000);
    }
    unsigned part = offset ? 2 : 1;
    if (s->total != total || (s->parts & part))
    {
        s->parts = 0;
        return -1;
    }
    memcpy(s->packet + offset, p + 9, count);
    s->received += count;
    s->parts |= part;
    if (s->received != total)
        return 0;
    s->parts = 0;
    return wm_ip_valid(s->packet, total) ? total : -1;
}
size_t wm_fragment(
    uint8_t out[WENDY_MESH_DATAGRAM], const uint8_t* p, size_t n, uint32_t id, size_t offset)
{
    if (!wm_ip_valid(p, n) || (offset != 0 && offset != 1091) || offset >= n)
        return 0;
    size_t count = n - offset;
    if (count > 1091)
        count = 1091;
    out[0] = 1;
    wm_put32(out + 1, id);
    wm_put16(out + 5, n);
    wm_put16(out + 7, offset);
    memcpy(out + 9, p + offset, count);
    return count + 9;
}
