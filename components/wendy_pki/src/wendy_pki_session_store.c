#include "wendy_pki_session_store.h"
#include <string.h>

static void forget(struct pki_session_store *s, struct pki_session_entry *e)
{
    if (e->bytes) {
        /* A volatile wipe must survive optimizing/LTO builds: encoded TLS
         * sessions contain resumption secrets, unlike ordinary public DER. */
        volatile uint8_t *p = e->bytes;
        for (size_t i = 0; i < e->size; i++)
            p[i] = 0;
        s->used -= wendy_net_memory_charge(e->size);
        wendy_net_memory_free(e->bytes);
    }
    memset(e, 0, sizeof *e);
}
static void expire(struct pki_session_store *s, int64_t now)
{
    for (unsigned i = 0; i < PKI_SESSION_SLOTS; i++)
        if (s->entries[i].bytes && now >= s->entries[i].expires_us)
            forget(s, &s->entries[i]);
}
/* Rebase ordering without allowing a uint64 rollover to reverse LRU. There
 * are only eight slots, so a stable rank computation is sufficient. */
static uint64_t tick(struct pki_session_store *s)
{
    if (s->clock == UINT64_MAX) {
        uint64_t ranks[PKI_SESSION_SLOTS] = {0};
        for (unsigned i = 0; i < PKI_SESSION_SLOTS; i++) {
            if (!s->entries[i].bytes)
                continue;
            ranks[i] = 1;
            for (unsigned j = 0; j < PKI_SESSION_SLOTS; j++)
                if (s->entries[j].bytes && s->entries[j].recency < s->entries[i].recency)
                    ranks[i]++;
        }
        for (unsigned i = 0; i < PKI_SESSION_SLOTS; i++)
            s->entries[i].recency = ranks[i];
        s->clock = PKI_SESSION_SLOTS;
    }
    return ++s->clock;
}
int pki_session_store_configure(struct pki_session_store *s, wendy_net_memory_t *owner,
                                 wendy_net_memory_placement_t placement, size_t limit)
{
    if (!s || !owner || !limit)
        return -1;
    pthread_mutex_lock(&s->lock);
    int result = -1;
    if (!s->used) {
        s->owner = owner;
        s->placement = placement;
        s->limit = limit;
        result = 0;
    }
    pthread_mutex_unlock(&s->lock);
    return result;
}
int pki_session_store_write(struct pki_session_store *s, const uint8_t scope[32],
                           const uint8_t key[32], size_t size,
                           int64_t now, int64_t expires,
                           int (*write)(void *, void *, size_t), void *context)
{
    if (!s || !scope || !key || !write || !size || now < 0 || expires <= now)
        return -1;
    size_t charge = wendy_net_memory_charge(size);
    if (!charge)
        return -1;
    pthread_mutex_lock(&s->lock);
    int result = -1;
    if (!s->owner || charge > s->limit)
        goto done;
    expire(s, now);
    int slot = -1;
    for (unsigned i = 0; i < PKI_SESSION_SLOTS; i++) {
        struct pki_session_entry *e = &s->entries[i];
        if (e->bytes && !memcmp(scope, e->scope, 32) && !memcmp(key, e->key, 32)) {
            forget(s, e);
            slot = (int)i;
            break;
        }
        if (!e->bytes)
            slot = (int)i;
    }
    while (slot < 0 || charge > s->limit - s->used) {
        int oldest = -1;
        for (unsigned i = 0; i < PKI_SESSION_SLOTS; i++)
            if (s->entries[i].bytes &&
                (oldest < 0 || s->entries[i].recency < s->entries[oldest].recency))
                oldest = (int)i;
        if (oldest < 0)
            goto done;
        forget(s, &s->entries[oldest]);
        slot = oldest;
    }
    uint8_t *copy = wendy_net_memory_malloc(s->owner, size, s->placement);
    if (!copy)
        goto done;
    memset(copy, 0, size);
    if (write(context, copy, size)) {
        volatile uint8_t *secret = copy;
        for (size_t i = 0; i < size; i++) secret[i] = 0;
        wendy_net_memory_free(copy);
        goto done;
    }
    struct pki_session_entry *e = &s->entries[slot];
    memcpy(e->scope, scope, 32);
    memcpy(e->key, key, 32);
    e->bytes = copy;
    e->size = size;
    e->expires_us = expires;
    e->recency = tick(s);
    s->used += charge;
    result = 0;
done:
    pthread_mutex_unlock(&s->lock);
    return result;
}
void pki_session_store_clear(struct pki_session_store *s)
{
    pthread_mutex_lock(&s->lock);
    for (unsigned i = 0; i < PKI_SESSION_SLOTS; i++)
        forget(s, &s->entries[i]);
    pthread_mutex_unlock(&s->lock);
}

int pki_session_store_visit(struct pki_session_store *s, const uint8_t scope[32],
    const uint8_t key[32], int64_t now, size_t maximum,
    int (*use)(void *, const void *, size_t), void *context)
{
    if (!s || !scope || !key || now < 0 || !maximum || !use)
        return -1;
    pthread_mutex_lock(&s->lock);
    expire(s, now);
    int result = 0;
    for (unsigned i = 0; i < PKI_SESSION_SLOTS; i++) {
        struct pki_session_entry *e = &s->entries[i];
        if (!e->bytes || memcmp(scope, e->scope, 32) || memcmp(key, e->key, 32))
            continue;
        result = -1;
        if (e->size <= maximum && !use(context, e->bytes, e->size)) {
            e->recency = tick(s);
            result = 1;
        }
        break;
    }
    pthread_mutex_unlock(&s->lock);
    return result;
}
