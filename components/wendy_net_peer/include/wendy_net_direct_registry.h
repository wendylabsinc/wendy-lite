#pragma once
#include "wendy_net_direct_session.h"
#include <stddef.h>
#define WN_DIRECT_POLICY_MAX 1024

/* Root actor owns this registry, never a transient carrier peer_state. Keys
 * contain canonical peer-principal hash and authenticated instance UUID; key
 * binding/config epochs belong to the session's separate identity digest. */
struct wn_direct_peer_key {
    uint8_t principal[32], instance[16];
};
struct wn_direct_peer {
    struct wn_direct_peer *next;
    struct wn_direct_peer_key key;
    uint64_t serial;
    unsigned pins;
    bool carrier_expired;
    size_t allocation;
    struct wn_direct_session session;
    struct wn_direct_flows flows;
    struct wn_direct_pool tx, rx;
    struct wn_direct_packet *packets;
    uint16_t packet_count;
    max_align_t storage[];
};
struct wn_direct_registry {
    struct wn_direct_peer *peers;
    uint64_t next_serial;
    unsigned count, limit;
    uint16_t slots;
    uint32_t tx_bytes, rx_bytes;
    /* Explicit backend capability/policy, zero disables. Each slot reserves
     * three datagram_max buffers, charged separately from reliable slabs in the
     * same ledger allocation. Configure before admitting peers. */
    uint16_t datagram_slots, datagram_max;
    uint64_t window, initial;
    bool closed;
};
/* small defaults:4 slots per namespace,8KiB TX/RX,4KiB window,1KiB initial.
 * Roomy defaults:16 slots,64KiB TX/RX,32KiB window,4KiB initial. These are local
 * policy, not wire constants; initialize before admission to override them. */
int wn_direct_registry_init(struct wn_direct_registry *, unsigned max_peers, bool small);
/* Allocates/charges metadata before session admission; payload slabs are
 * charged as flows reserve receive credit or retain outgoing bytes.
 * cfg storage/flows fields are supplied here. If policy_bytes is nonzero,
 * copy that many bytes of cfg.check_arg into the same ledger allocation and
 * use the owned copy for policy checks. The snapshot must contain only values,
 * no borrowed pointers, and fit WN_DIRECT_POLICY_MAX. Reattachment retains the
 * ORIGINAL snapshot. With zero bytes check_arg must outlive the retained peer.
 * RNG context must always outlive the peer (root-owned).
 * Success gives one pin; release after fenced adapter teardown or failed attach.
 * Changed digest/role/transport closes the old epoch and rejects this attempt. */
int wn_direct_registry_acquire(struct wn_direct_registry *, const struct wn_direct_peer_key *,
                               const struct wn_direct_session_config *, size_t policy_bytes,
                               int64_t now, struct wn_direct_peer **);
/* Upper TLS admission can ONLY pin an established retained epoch. Unlike carrier
 * acquire, a mismatched candidate must neither create nor invalidate an epoch.
 * cfg identity/role/transport/deadline are locally authenticated. Nonzero
 * expected_serial pins outgoing setup to its original epoch; zero permits an
 * incoming lookup. Caller independently verifies the upper ALPN and then the
 * exporter/capability proof. This pin alone authorizes no cutover or app data.
 * Success preserves original policy and only shortens its security deadline. */
int wn_direct_registry_pin_promoted(struct wn_direct_registry *, const struct wn_direct_peer_key *,
                                    const struct wn_direct_session_config *,
                                    uint64_t expected_serial, int64_t now,
                                    struct wn_direct_peer **);
void wn_direct_registry_release(struct wn_direct_registry *, struct wn_direct_peer *);
/* Backend jobs store serial+flow ID, not raw peer pointers. Lookup is an actor-
 * turn borrow; a retired serial never resolves to a replacement peer epoch. */
struct wn_direct_peer *wn_direct_registry_lookup(struct wn_direct_registry *, uint64_t serial);
/* Tick detached sessions too. Positive=progress; setup-expired attached peers
 * set carrier_expired and remain pinned until their carrier owner fences them. Closed peers are
 * reaped only when no carrier/handshake pin remains. */
int wn_direct_registry_tick(struct wn_direct_registry *, int64_t now);
/* Rejects further admission, closes all logical sockets. False means a carrier
 * pin still needs teardown/release before the root registry can be discarded. */
bool wn_direct_registry_close(struct wn_direct_registry *);

/* Actor-turn query: retained app flows still need recovery resources even after
 * the mesh address grace expires. Closed/pinned metadata alone does not. */
bool wn_direct_registry_has_flows(const struct wn_direct_registry *);
