#include "wendy_net_direct_wire.h"
#include <string.h>
static uint64_t get(const uint8_t *p, size_t n)
{
    uint64_t v = 0;
    while (n--)
        v = (v << 8) | *p++;
    return v;
}
static void put(uint8_t *p, uint64_t v, size_t n)
{
    while (n) {
        p[--n] = (uint8_t)v;
        v >>= 8;
    }
}
int wn_direct_frame_size(const struct wn_direct_frame *f, size_t *out)
{
    if (!f || !out)
        return -1;
    *out = 0;
    if (!f->attachment_id ||
        (f->kind != WN_DIRECT_STATE && f->kind != WN_DIRECT_OPEN_CREDIT &&
         f->kind != WN_DIRECT_DATAGRAM_LIMIT && f->kind != WN_DIRECT_EPOCH_IDLE && !f->flow_id))
        return -1;
    size_t n;
    switch (f->kind) {
    case WN_DIRECT_EPOCH_IDLE:
        if (f->flow_id)
            return -1;
        n = 5;
        break;
    case WN_DIRECT_DATAGRAM_LIMIT:
        if (f->flow_id)
            return -1;
        n = 7;
        break;
    case WN_DIRECT_DATA:
        if (!f->payload || !f->payload_size || f->payload_size > WN_DIRECT_MAX_DATA)
            return -1;
        n = 9 + f->payload_size;
        break;
    case WN_DIRECT_STATE:
        if (!f->state_count || f->state_count > WN_DIRECT_MAX_STATES)
            return -1;
        for (size_t i = 0; i < f->state_count; i++) {
            if (!f->states[i].flow_id || f->states[i].received > f->states[i].limit)
                return -1;
            for (size_t j = 0; j < i; j++)
                if (f->states[i].flow_id == f->states[j].flow_id)
                    return -1;
        }
        n = 6 + 21 * f->state_count;
        break;
    case WN_DIRECT_FIN:
        n = 17;
        break;
    case WN_DIRECT_OPEN:
        switch (f->service) {
        case WN_DIRECT_TCP:
            if (!f->port || f->datagram_size)
                return -1;
            break;
        case WN_DIRECT_UDP:
            if (!f->port || !f->datagram_size)
                return -1;
            break;
        case WN_DIRECT_WENDYCOM:
        case WN_DIRECT_GRPC_ADMIN:
            if (f->port || f->datagram_size)
                return -1;
            break;
        default:
            return -1;
        }
        n = 14;
        break;
    case WN_DIRECT_OPEN_RESULT:
    case WN_DIRECT_RESET:
        n = 11;
        break;
    case WN_DIRECT_OPEN_CREDIT:
        n = 13;
        break;
    case WN_DIRECT_DATAGRAM:
        if (!f->value || f->payload_size > WN_DIRECT_MAX_DATA || (f->payload_size && !f->payload) ||
            f->fragment_offset + f->payload_size > f->datagram_size ||
            (f->datagram_size && !f->payload_size))
            return -1;
        n = 21 + f->payload_size;
        break;
    case WN_DIRECT_CLOSE_ACK:
        n = 9;
        break;
    default:
        return -1;
    }
    *out = n;
    return 0;
}
int wn_direct_frame_encode(const struct wn_direct_frame *f, uint8_t *b, size_t cap, size_t *out)
{
    if (!out)
        return -1;
    *out = 0;
    size_t n;
    if (wn_direct_frame_size(f, &n) || !b || cap < n)
        return -1;
    b[0] = f->kind;
    put(b + 1, f->attachment_id, 4);
    if (f->kind != WN_DIRECT_STATE && f->kind != WN_DIRECT_OPEN_CREDIT &&
        f->kind != WN_DIRECT_DATAGRAM_LIMIT && f->kind != WN_DIRECT_EPOCH_IDLE)
        put(b + 5, f->flow_id, 4);
    switch (f->kind) {
    case WN_DIRECT_DATAGRAM_LIMIT:
        put(b + 5, f->datagram_size, 2);
        break;
    case WN_DIRECT_DATA:
        memcpy(b + 9, f->payload, f->payload_size);
        break;
    case WN_DIRECT_STATE:
        b[5] = f->state_count;
        for (size_t i = 0; i < f->state_count; i++) {
            uint8_t *p = b + 6 + 21 * i;
            const struct wn_direct_state_entry *s = &f->states[i];
            put(p, s->flow_id, 4);
            put(p + 4, s->received, 8);
            put(p + 12, s->limit, 8);
            p[20] = s->fin_seen ? 1 : 0;
        }
        break;
    case WN_DIRECT_FIN:
        put(b + 9, f->value, 8);
        break;
    case WN_DIRECT_OPEN:
        b[9] = f->service;
        put(b + 10, f->port, 2);
        put(b + 12, f->datagram_size, 2);
        break;
    case WN_DIRECT_OPEN_RESULT:
    case WN_DIRECT_RESET:
        put(b + 9, f->code, 2);
        break;
    case WN_DIRECT_OPEN_CREDIT:
        put(b + 5, f->value, 8);
        break;
    case WN_DIRECT_DATAGRAM:
        put(b + 9, f->value, 8);
        put(b + 17, f->datagram_size, 2);
        put(b + 19, f->fragment_offset, 2);
        if (f->payload_size)
            memcpy(b + 21, f->payload, f->payload_size);
        break;
    default:
        break;
    }
    *out = n;
    return 0;
}
static int decode(const uint8_t *b, size_t n, struct wn_direct_frame *f)
{
    if (!b || n < 5 || n > WN_DIRECT_MAX_FRAME)
        return -1;
    f->kind = b[0];
    f->attachment_id = (uint32_t)get(b + 1, 4);
    if (f->kind != WN_DIRECT_STATE && f->kind != WN_DIRECT_OPEN_CREDIT &&
        f->kind != WN_DIRECT_DATAGRAM_LIMIT && f->kind != WN_DIRECT_EPOCH_IDLE) {
        if (n < 9)
            return -1;
        f->flow_id = (uint32_t)get(b + 5, 4);
    }
    switch (f->kind) {
    case WN_DIRECT_EPOCH_IDLE:
        if (n != 5)
            return -1;
        break;
    case WN_DIRECT_DATAGRAM_LIMIT:
        if (n != 7)
            return -1;
        f->datagram_size = (uint16_t)get(b + 5, 2);
        break;
    case WN_DIRECT_DATA:
        f->payload = b + 9;
        f->payload_size = n - 9;
        break;
    case WN_DIRECT_STATE:
        if (n < 6)
            return -1;
        f->state_count = b[5];
        if (!f->state_count || f->state_count > WN_DIRECT_MAX_STATES ||
            n != 6 + 21 * (size_t)f->state_count)
            return -1;
        for (size_t i = 0; i < f->state_count; i++) {
            const uint8_t *p = b + 6 + 21 * i;
            struct wn_direct_state_entry *s = &f->states[i];
            if (p[20] > 1)
                return -1;
            s->flow_id = (uint32_t)get(p, 4);
            s->received = get(p + 4, 8);
            s->limit = get(p + 12, 8);
            s->fin_seen = p[20] != 0;
        }
        break;
    case WN_DIRECT_FIN:
        if (n != 17)
            return -1;
        f->value = get(b + 9, 8);
        break;
    case WN_DIRECT_OPEN:
        if (n != 14)
            return -1;
        f->service = b[9];
        f->port = (uint16_t)get(b + 10, 2);
        f->datagram_size = (uint16_t)get(b + 12, 2);
        break;
    case WN_DIRECT_OPEN_RESULT:
    case WN_DIRECT_RESET:
        if (n != 11)
            return -1;
        f->code = (uint16_t)get(b + 9, 2);
        break;
    case WN_DIRECT_OPEN_CREDIT:
        if (n != 13)
            return -1;
        f->value = get(b + 5, 8);
        break;
    case WN_DIRECT_DATAGRAM:
        if (n < 21)
            return -1;
        f->value = get(b + 9, 8);
        f->datagram_size = (uint16_t)get(b + 17, 2);
        f->fragment_offset = (uint16_t)get(b + 19, 2);
        f->payload = b + 21;
        f->payload_size = n - 21;
        break;
    case WN_DIRECT_CLOSE_ACK:
        if (n != 9)
            return -1;
        break;
    default:
        return -1;
    }
    size_t expected;
    return wn_direct_frame_size(f, &expected) || expected != n ? -1 : 0;
}
int wn_direct_frame_decode(const uint8_t *b, size_t n, struct wn_direct_frame *out)
{
    if (!out)
        return -1;
    struct wn_direct_frame f = {0};
    if (decode(b, n, &f)) {
        memset(out, 0, sizeof *out);
        return -1;
    }
    *out = f;
    return 0;
}
