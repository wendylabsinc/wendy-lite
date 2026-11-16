#include "wendy_net_direct_identity.h"
#include <psa/crypto.h>
#include <string.h>
static int nonzero(const uint8_t *p, size_t n)
{
    uint8_t v = 0;
    while (n--)
        v |= *p++;
    return v != 0;
}
static int valid(const struct wn_direct_endpoint_identity *i)
{
    return i && i->role <= 1 && nonzero(i->principal, 32) && nonzero(i->key, 32) &&
           nonzero(i->instance, 16);
}
static int endpoint(const struct wn_direct_authenticated_endpoint *in,
                    struct wn_direct_endpoint_identity *out)
{
    if (!in || !in->principal || !in->principal_size || in->principal_size > 1024 ||
        memchr(in->principal, 0, in->principal_size) || in->role > 1 || !nonzero(in->key, 32) ||
        !nonzero(in->instance, 16))
        return -1;
    out->role = in->role;
    memcpy(out->key, in->key, 32);
    memcpy(out->instance, in->instance, 16);
    size_t written = 0;
    return psa_hash_compute(PSA_ALG_SHA_256, (const uint8_t *)in->principal,
                            in->principal_size, out->principal, 32, &written) == PSA_SUCCESS &&
                   written == 32 ? 0 : -1;
}
int wn_direct_identity_pair(const struct wn_direct_authenticated_endpoint *local,
                            const struct wn_direct_authenticated_endpoint *peer,
                            struct wn_direct_identity_pair *out)
{
    if (!out)
        return -1;
    memset(out, 0, sizeof *out);
    struct wn_direct_identity_pair pair = {0};
    if (endpoint(local, &pair.local) || endpoint(peer, &pair.peer))
        return -1;
    int order = 0;
    if (local->role || peer->role) {
        size_t n = local->principal_size < peer->principal_size ? local->principal_size
                                                                : peer->principal_size;
        order = memcmp(local->principal, peer->principal, n);
        if (!order)
            order = (local->principal_size > peer->principal_size) -
                    (local->principal_size < peer->principal_size);
    }
    if (!order)
        order = memcmp(local->instance, peer->instance, 16);
    if (!order)
        return -1;
    pair.local_role = order > 0;
    if (wn_direct_identity_digest(order < 0 ? &pair.local : &pair.peer,
                                  order < 0 ? &pair.peer : &pair.local, pair.digest))
        return -1;
    *out = pair;
    return 0;
}
int wn_direct_identity_digest(const struct wn_direct_endpoint_identity *c,
                              const struct wn_direct_endpoint_identity *p, uint8_t out[32])
{
    if (!out)
        return -1;
    memset(out, 0, 32);
    if (!valid(c) || !valid(p) ||
        (!memcmp(c->principal, p->principal, 32) && !memcmp(c->instance, p->instance, 16)))
        return -1;
    psa_hash_operation_t h = PSA_HASH_OPERATION_INIT;
    static const uint8_t domain[] = "wendy/direct/identities/1";
    psa_status_t r = psa_hash_setup(&h, PSA_ALG_SHA_256);
    if (!r)
        r = psa_hash_update(&h, domain, sizeof domain);
    const struct wn_direct_endpoint_identity *ids[2] = {c, p};
    for (unsigned n = 0; n < 2 && !r; n++) {
        const struct wn_direct_endpoint_identity *i = ids[n];
        r = psa_hash_update(&h, &i->role, 1);
        if (!r)
            r = psa_hash_update(&h, i->principal, 32);
        if (!r)
            r = psa_hash_update(&h, i->instance, 16);
        if (!r)
            r = psa_hash_update(&h, i->key, 32);
    }
    size_t written = 0;
    if (!r)
        r = psa_hash_finish(&h, out, 32, &written);
    psa_hash_abort(&h);
    if (written != 32)
        r = PSA_ERROR_GENERIC_ERROR;
    if (r)
        memset(out, 0, 32);
    return r ? -1 : 0;
}
