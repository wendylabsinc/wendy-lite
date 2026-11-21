#include "wendy_net_direct_control.h"
#include <string.h>
static bool nonzero(const uint8_t *p, size_t n)
{
    uint8_t v = 0;
    for (size_t i = 0; i < n; i++)
        v |= p[i];
    return v != 0;
}
static void put16(uint8_t *p, uint16_t v)
{
    p[0] = v >> 8;
    p[1] = v;
}
static void put32(uint8_t *p, uint32_t v)
{
    for (unsigned i = 0; i < 4; i++)
        p[i] = (uint8_t)(v >> (24 - i * 8));
}
static void put64(uint8_t *p, uint64_t v)
{
    for (unsigned i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (56 - i * 8));
}
static uint16_t get16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] << 8 | p[1]);
}
static uint32_t get32(const uint8_t *p)
{
    uint32_t v = 0;
    for (unsigned i = 0; i < 4; i++)
        v = v << 8 | p[i];
    return v;
}
static uint64_t get64(const uint8_t *p)
{
    uint64_t v = 0;
    for (unsigned i = 0; i < 8; i++)
        v = v << 8 | p[i];
    return v;
}
int wn_direct_control_size(const struct wn_direct_control *c, size_t *out)
{
    if (!c || !out || !c->attachment_id)
        return -1;
    size_t n;
    switch (c->kind) {
    case WN_DIRECT_OFFER:
        if (!c->generation || (c->mode != WN_DIRECT_BLE && c->mode != WN_DIRECT_PROMOTED) ||
            !nonzero(c->session_id, 32) || !nonzero(c->nonce, 16) ||
            (c->create && (c->mode != WN_DIRECT_BLE || !nonzero(c->capability, 32))) ||
            (!c->create && nonzero(c->capability, 32)))
            return -1;
        n = 137;
        break;
    case WN_DIRECT_VIEW:
        if (!nonzero(c->nonce, 16))
            return -1;
        n = 63;
        break;
    case WN_DIRECT_RECORDS: {
        if (!c->record_count || c->record_count > WN_DIRECT_RECOVERY_BATCH ||
            (uint32_t)c->start + c->record_count > UINT16_MAX)
            return -1;
        uint32_t previous = 0;
        uint8_t scratch[WN_DIRECT_RECOVERY_RECORD_BYTES];
        for (unsigned i = 0; i < c->record_count; i++) {
            if (c->records[i].id <= previous ||
                wn_direct_recovery_encode(&c->records[i], scratch, sizeof scratch))
                return -1;
            previous = c->records[i].id;
        }
        n = 8 + c->record_count * WN_DIRECT_RECOVERY_RECORD_BYTES;
        break;
    }
    case WN_DIRECT_READY_PROOF:
    case WN_DIRECT_COMMIT_PROOF:
        n = 69;
        break;
    case WN_DIRECT_COMMIT_ACK:
        n = 37;
        break;
    default:
        return -1;
    }
    *out = n;
    return 0;
}
static void put_view(uint8_t *p, const struct wn_direct_control *c)
{
    for (unsigned i = 0; i < 2; i++) {
        const struct wn_direct_namespace_checkpoint *v = &c->namespaces[i];
        put32(p + i * 20, v->high_water);
        put64(p + i * 20 + 4, v->admitted);
        put64(p + i * 20 + 12, v->grant);
    }
    put16(p + 40, c->count);
}
static void get_view(const uint8_t *p, struct wn_direct_control *c)
{
    for (unsigned i = 0; i < 2; i++) {
        struct wn_direct_namespace_checkpoint *v = &c->namespaces[i];
        v->high_water = get32(p + i * 20);
        v->admitted = get64(p + i * 20 + 4);
        v->grant = get64(p + i * 20 + 12);
    }
    c->count = get16(p + 40);
}
int wn_direct_control_encode(const struct wn_direct_control *c, uint8_t *p, size_t cap,
                             size_t *written)
{
    size_t n;
    if (!p || !written || wn_direct_control_size(c, &n) || cap < n)
        return -1;
    p[0] = c->kind;
    put32(p + 1, c->attachment_id);
    switch (c->kind) {
    case WN_DIRECT_OFFER:
        put64(p + 5, c->generation);
        p[13] = (uint8_t)c->mode;
        p[14] = c->create ? 1 : 0;
        memcpy(p + 15, c->session_id, 32);
        memcpy(p + 47, c->capability, 32);
        memcpy(p + 79, c->nonce, 16);
        put_view(p + 95, c);
        break;
    case WN_DIRECT_VIEW:
        memcpy(p + 5, c->nonce, 16);
        put_view(p + 21, c);
        break;
    case WN_DIRECT_RECORDS:
        put16(p + 5, c->start);
        p[7] = c->record_count;
        for (unsigned i = 0; i < c->record_count; i++)
            (void)wn_direct_recovery_encode(&c->records[i],
                                            p + 8 + i * WN_DIRECT_RECOVERY_RECORD_BYTES,
                                            WN_DIRECT_RECOVERY_RECORD_BYTES);
        break;
    case WN_DIRECT_READY_PROOF:
    case WN_DIRECT_COMMIT_PROOF:
        memcpy(p + 5, c->context, 32);
        memcpy(p + 37, c->proof, 32);
        break;
    case WN_DIRECT_COMMIT_ACK:
        memcpy(p + 5, c->context, 32);
        break;
    }
    *written = n;
    return 0;
}
int wn_direct_control_decode(const uint8_t *p, size_t n, struct wn_direct_control *c)
{
    if (!c)
        return -1;
    memset(c, 0, sizeof *c);
    if (!p || n < 5 || n > 533)
        return -1;
    c->kind = p[0];
    c->attachment_id = get32(p + 1);
    switch (c->kind) {
    case WN_DIRECT_OFFER:
        if (n != 137 || p[14] > 1)
            goto bad;
        c->generation = get64(p + 5);
        c->mode = (enum wn_direct_mode)p[13];
        c->create = p[14] != 0;
        memcpy(c->session_id, p + 15, 32);
        memcpy(c->capability, p + 47, 32);
        memcpy(c->nonce, p + 79, 16);
        get_view(p + 95, c);
        break;
    case WN_DIRECT_VIEW:
        if (n != 63)
            goto bad;
        memcpy(c->nonce, p + 5, 16);
        get_view(p + 21, c);
        break;
    case WN_DIRECT_RECORDS:
        if (n < 8 || !p[7] || p[7] > WN_DIRECT_RECOVERY_BATCH ||
            n != 8 + (size_t)p[7] * WN_DIRECT_RECOVERY_RECORD_BYTES)
            goto bad;
        c->start = get16(p + 5);
        c->record_count = p[7];
        for (unsigned i = 0; i < c->record_count; i++)
            if (wn_direct_recovery_decode(p + 8 + i * WN_DIRECT_RECOVERY_RECORD_BYTES,
                                          WN_DIRECT_RECOVERY_RECORD_BYTES, &c->records[i]))
                goto bad;
        break;
    case WN_DIRECT_READY_PROOF:
    case WN_DIRECT_COMMIT_PROOF:
        if (n != 69)
            goto bad;
        memcpy(c->context, p + 5, 32);
        memcpy(c->proof, p + 37, 32);
        break;
    case WN_DIRECT_COMMIT_ACK:
        if (n != 37)
            goto bad;
        memcpy(c->context, p + 5, 32);
        break;
    default:
        goto bad;
    }
    size_t expected;
    if (wn_direct_control_size(c, &expected) || expected != n)
        goto bad;
    return 0;
bad:
    memset(c, 0, sizeof *c);
    return -1;
}
