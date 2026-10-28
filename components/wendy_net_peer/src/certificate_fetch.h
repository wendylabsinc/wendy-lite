/* SPDX-License-Identifier: Apache-2.0 */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define WNCF_CHAIN_MAX 16
#define WNCF_PART_MAX 65536
#define WNCF_CHUNK 1024
struct wncf_chain {
    char principal[106];
    unsigned count;
    uint8_t hashes[WNCF_CHAIN_MAX][32];
};
struct wncf_store {
    void *context;
    /* 1 present, 0 absent, negative storage failure. NULL output queries size.
     * Returned parts are public bytes, never an identity/trust assertion. */
    int (*read)(void *,const uint8_t hash[32],size_t offset,
                uint8_t out[WNCF_CHUNK],size_t *total);
    /* 0 stored, positive temporarily busy, negative storage failure. */
    int (*put)(void *,const uint8_t hash[32],const void *,size_t);
    /* Optional immutable cache loan. Already downloaded parts remain pinned
     * until stop/verification handoff; no metadata is reserved while idle. */
    void *(*retain)(void *,const uint8_t hash[32]);
    void (*release)(void *);
};
struct wncf_hold;
struct wncf_fetch {
    struct wncf_chain *chain;
    struct wncf_hold *hold;
    uint8_t *bytes;
    size_t offset,total;
    unsigned index;
    bool waiting;
    int64_t deadline,progress;
};
struct wncf_request {uint8_t hash[32];size_t offset;};

/* One bounded public-chain transfer per supplier. The caller independently
 * validates the principal/tenant and performs ordinary full-path verification
 * on completion. No certificate payload memory is reserved while idle. */
int wncf_start(struct wncf_fetch *,const struct wncf_chain *,int64_t now_ms);
/* Fetch exact public parts by hash without implying a device identity. The
 * caller supplies and verifies the independently obtained chain descriptor. */
int wncf_start_hashes(struct wncf_fetch *,const uint8_t hashes[][32],unsigned,
    int64_t now_ms);
void wncf_stop(struct wncf_fetch *);
/* Exact supplier miss: release this fetch and all partial buffers immediately. */
bool wncf_missing(struct wncf_fetch *,const struct wncf_request *);
/* 1 request available, 2 all public parts stored, 0 waiting/busy, -1 ended.
 * A request becomes in-flight only after queue admission and wncf_sent(). */
int wncf_next(struct wncf_fetch *,const struct wncf_store *,int64_t now_ms,
              struct wncf_request *);
void wncf_sent(struct wncf_fetch *,int64_t now_ms);
int wncf_receive(struct wncf_fetch *,const struct wncf_store *,
    const uint8_t hash[32],size_t offset,size_t total,const void *,size_t,
    int64_t now_ms);
size_t wncf_memory(const struct wncf_fetch *);
