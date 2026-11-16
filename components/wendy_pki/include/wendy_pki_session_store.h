#pragma once
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include "wendy_net_memory.h"

/* RAM-only TLS state cache. The integration hashes exact identity epoch,
 * peer/role, protocol and ticket-issuer domain into scope; this layer never
 * interprets a ticket as application-session attachment authority.
 * Slots and payload are bounded independently. All payloads use one explicit
 * memory owner; the store must be cleared before that owner's shutdown. */
#define PKI_SESSION_SLOTS 8
#define PKI_SESSION_KEY_BYTES 32
struct pki_session_entry {
    uint8_t key[PKI_SESSION_KEY_BYTES], scope[32];
    uint8_t *bytes;
    size_t size;
    int64_t expires_us;
    uint64_t recency;
};
struct pki_session_store {
    pthread_mutex_t lock;
    struct pki_session_entry entries[PKI_SESSION_SLOTS];
    wendy_net_memory_t *owner;
    wendy_net_memory_placement_t placement;
    size_t limit, used;
    uint64_t clock;
};
#define PKI_SESSION_STORE_INITIALIZER {.lock = PTHREAD_MUTEX_INITIALIZER}
/* Configure only while empty, before publishing the store to workers. */
int pki_session_store_configure(struct pki_session_store *, wendy_net_memory_t *,
                                 wendy_net_memory_placement_t, size_t limit);
void pki_session_store_clear(struct pki_session_store *);

/* Inspect a bounded entry without a temporary allocation. The callback runs
 * under the store lock and must neither reenter the cache nor retain any input
 * pointer. Decode/copy into caller-owned state before returning. Eviction and
 * clear cannot wipe the entry during the callback. Callback returns 0 on success.
 * Result: 1 success, 0 miss/expired/wrong scope, -1 invalid/oversize/callback error. */
int pki_session_store_visit(struct pki_session_store *, const uint8_t scope[32],
    const uint8_t key[32], int64_t now_us, size_t maximum,
    int (*use)(void *, const void *, size_t), void *context);

/* Serialize directly into one final cache allocation. Callback runs under the
 * store lock: do not reenter the store or retain the output pointer. It receives
 * zeroed storage and returns 0 only after filling the exact requested size.
 * Failed writes are wiped and never published. Existing bounded eviction rules
 * apply even if writing fails. No recovery-workspace reclamation is attempted.
 * Result: 0 stored, -1 invalid/budget/allocation/callback failure. */
int pki_session_store_write(struct pki_session_store *, const uint8_t scope[32],
    const uint8_t key[32], size_t size, int64_t now_us, int64_t expires_us,
    int (*write)(void *, void *, size_t), void *context);
