#include "wendy_net_direct_recovery_wire.h"
#include <psa/crypto.h>
#include <string.h>
static void put(uint8_t *p, uint64_t v, size_t n)
{
    while (n) {
        p[--n] = (uint8_t)v;
        v >>= 8;
    }
}
static uint64_t get(const uint8_t *p, size_t n)
{
    uint64_t v = 0;
    while (n--)
        v = (v << 8) | *p++;
    return v;
}
static bool valid_record(const struct wn_direct_recovery_record *r)
{
    return r && r->id && wn_direct_snapshot_valid(&r->flow) && (r->reset || !r->reset_code) &&
           (r->open_complete || (!r->result && !r->local_closed && !r->remote_closed));
}
int wn_direct_recovery_encode(const struct wn_direct_recovery_record *r, uint8_t *p, size_t n)
{
    if (!p || n < WN_DIRECT_RECOVERY_RECORD_BYTES || !valid_record(r))
        return -1;
    put(p, r->id, 4);
    memcpy(p + 4, r->open_digest, 32);
    put(p + 36, r->result, 2);
    p[38] = (r->open_complete ? 1 : 0) | (r->local_closed ? 2 : 0) | (r->remote_closed ? 4 : 0) |
            (r->flow.send_finished ? 8 : 0) | (r->flow.receive_finished ? 16 : 0) |
            (r->reset ? 32 : 0);
    put(p + 39, r->reset_code, 2);
    const struct wn_direct_snapshot *s = &r->flow;
    uint64_t v[9] = {s->acked,    s->offered, s->tail,       s->remote_limit, s->consumed,
                     s->received, s->limit,   s->send_final, s->receive_final};
    for (size_t i = 0; i < 9; i++)
        put(p + 41 + 8 * i, v[i], 8);
    return 0;
}
int wn_direct_recovery_decode(const uint8_t *p, size_t n, struct wn_direct_recovery_record *out)
{
    if (!out)
        return -1;
    memset(out, 0, sizeof *out);
    if (!p || n != WN_DIRECT_RECOVERY_RECORD_BYTES || (p[38] & ~63))
        return -1;
    struct wn_direct_recovery_record r = {.id = (uint32_t)get(p, 4),
                                          .result = (uint16_t)get(p + 36, 2),
                                          .reset = (p[38] & 32) != 0,
                                          .reset_code = (uint16_t)get(p + 39, 2),
                                          .open_complete = (p[38] & 1) != 0,
                                          .local_closed = (p[38] & 2) != 0,
                                          .remote_closed = (p[38] & 4) != 0};
    memcpy(r.open_digest, p + 4, 32);
    uint64_t v[9];
    for (size_t i = 0; i < 9; i++)
        v[i] = get(p + 41 + 8 * i, 8);
    r.flow = (struct wn_direct_snapshot){.acked = v[0],
                                         .offered = v[1],
                                         .tail = v[2],
                                         .remote_limit = v[3],
                                         .consumed = v[4],
                                         .received = v[5],
                                         .limit = v[6],
                                         .send_final = v[7],
                                         .receive_final = v[8],
                                         .send_finished = (p[38] & 8) != 0,
                                         .receive_finished = (p[38] & 16) != 0};
    if (!valid_record(&r))
        return -1;
    *out = r;
    return 0;
}
bool wn_direct_recovery_view_valid(const struct wn_direct_recovery_view *v)
{
    if (!v || v->count > 65535 || (v->count && !v->records))
        return false;
    for (size_t i = 0; i < 2; i++) {
        const struct wn_direct_namespace_checkpoint *s = &v->namespaces[i];
        if (s->admitted > s->grant)
            return false;
        if (!s->high_water) {
            if (s->admitted)
                return false;
        } else if ((s->high_water & 1) != i || !s->admitted ||
                   s->admitted > (uint64_t)s->high_water / 2 + (i == 1))
            return false;
    }
    uint32_t previous = 0;
    uint64_t counts[2] = {0};
    for (size_t i = 0; i < v->count; i++) {
        const struct wn_direct_recovery_record *r = &v->records[i];
        if (!valid_record(r) || r->id <= previous || r->id > v->namespaces[r->id & 1].high_water)
            return false;
        previous = r->id;
        if (++counts[r->id & 1] > v->namespaces[r->id & 1].admitted)
            return false;
    }
    return true;
}
int wn_direct_recovery_digest(const struct wn_direct_recovery_view *c,
                              const struct wn_direct_recovery_view *p, uint8_t out[32])
{
    if (!out)
        return -1;
    memset(out, 0, 32);
    if (!wn_direct_recovery_view_valid(c) || !wn_direct_recovery_view_valid(p))
        return -1;
    const char domain[] = "wendy/direct/recovery-view/1";
    psa_hash_operation_t hash = PSA_HASH_OPERATION_INIT;
    size_t written = 0;
    int result = -1;
    uint8_t header[42], record[WN_DIRECT_RECOVERY_RECORD_BYTES];
    if (psa_hash_setup(&hash, PSA_ALG_SHA_256) ||
        psa_hash_update(&hash, (const uint8_t *)domain, sizeof domain))
        goto done;
    const struct wn_direct_recovery_view *views[2] = {c, p};
    for (size_t side = 0; side < 2; side++) {
        const struct wn_direct_recovery_view *v = views[side];
        for (size_t i = 0; i < 2; i++) {
            const struct wn_direct_namespace_checkpoint *s = &v->namespaces[i];
            put(header + 20 * i, s->high_water, 4);
            put(header + 20 * i + 4, s->admitted, 8);
            put(header + 20 * i + 12, s->grant, 8);
        }
        put(header + 40, v->count, 2);
        if (psa_hash_update(&hash, header, sizeof header))
            goto done;
        for (size_t i = 0; i < v->count; i++)
            if (wn_direct_recovery_encode(&v->records[i], record, sizeof record) ||
                psa_hash_update(&hash, record, sizeof record))
                goto done;
    }
    if (psa_hash_finish(&hash, out, 32, &written) == PSA_SUCCESS && written == 32)
        result = 0;
done:
    psa_hash_abort(&hash);
    if (result)
        memset(out, 0, 32);
    return result;
}
