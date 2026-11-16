#pragma once
#include "wendy_net_direct_session.h"
/* One bounded record in each direction. App owner keeps TLS/BIO alive and
 * exclusively serializes this driver with session ticks and cleanup. */
struct wn_direct_records {
    /* Zero-initialize and supply realloc semantics (size zero frees). Retain
     * exact records across partial I/O and release idle buffers. The owner frees
     * remaining buffers on teardown. TX stays immutable across TLS WANT_WRITE. */
    uint8_t *tx, *rx;
    size_t tx_capacity, rx_capacity;
    void *(*resize)(void *, size_t);
    size_t sent, queued, received, wanted;
};
/* Positive progress, zero would block, negative fatal. Records are uint16 BE
 * length followed by 1..MAX_FRAME bytes, matching WendyOS DirectUpperRecords.
 * No TLS ownership transfer; close/reset the session before disposing TLS. */
int wn_direct_records_poll(struct wn_direct_records *, struct wn_direct_session *, uint64_t token,
                           const struct wn_direct_upper *, int64_t now,
                           int (*open)(void *, uint32_t), void *);
