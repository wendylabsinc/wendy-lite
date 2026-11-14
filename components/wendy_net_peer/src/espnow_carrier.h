/* SPDX-License-Identifier: Apache-2.0
 * ESP-NOW binding of the portable stream layer: radio upkeep, one bounded
 * receive ring, peer-table upkeep and discovery adverts. Actor-only. Wi-Fi
 * control calls run on the existing I/O worker, never in the actor.
 */
#pragma once
#include "espnow_stream.h"
#include "wendy_pki.h"
#include <stdbool.h>
#include <stdint.h>

struct wnen_intent {
    const char *tenant, *device; /* Enrolled identifiers for the advert scope. */
    bool fixed_channel;          /* Leave any Wi-Fi network; stay on the configured channel. */
    bool accepting;              /* Admit incoming streams and advertise. */
    bool linked;                 /* An ESP-NOW link is up: advertise less often. */
};
/* A same-tenant advert. Every field is an unauthenticated hint. */
typedef void (*wnen_seen)(void *context, const uint8_t mac[6], const uint8_t device[16],
                          uint8_t flags);
/* Allocates from the mesh ledger. False leaves nothing behind; retry later. */
bool wnen_start(void (*wake)(void));
/* False while the radio effect is still returning; call again. Idempotent. */
bool wnen_stop(void);
/* One nonblocking pass. True when received frames were handled. */
bool wnen_poll(const struct wnen_intent *, wnen_seen, void *context);
/* Sends what this pass queued, then reports when to run again. */
int64_t wnen_deadline(void);
struct wnes_conn *wnen_dial(const uint8_t mac[6]);
struct wnes_conn *wnen_take(uint8_t mac[6]);
struct wendy_pki_stream wnen_stream(struct wnes_conn *);
void wnen_release(struct wnes_conn *);
