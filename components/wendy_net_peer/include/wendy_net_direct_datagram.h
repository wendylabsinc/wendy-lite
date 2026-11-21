#pragma once
#include "wendy_net_direct_wire.h"
/* Actor-owned one-message UDP reassembly. Caller reserves storage from its UDP
 * budget. No allocation, ACK, replay or out-of-order fragment queue. IDs remain
 * monotonic across carriers; a gap/overlap discards the incomplete message. */
struct wn_direct_datagram {
    uint8_t *storage;
    size_t capacity, total, received;
    uint32_t flow, alias;
    uint64_t generation, last_id;
    bool active;
};
int wn_direct_datagram_init(struct wn_direct_datagram *, uint32_t flow, uint8_t *, size_t);
/* Only after authenticated commit; generation comes from the local owner. */
int wn_direct_datagram_bind(struct wn_direct_datagram *, uint64_t generation, uint32_t alias);
void wn_direct_datagram_suspend(struct wn_direct_datagram *);
/* 1 complete (including empty), 0 discarded/incomplete, -1 invalid input.
 * Output borrows storage until the next call. Old generations cannot mutate it. */
int wn_direct_datagram_receive(struct wn_direct_datagram *, uint64_t generation,
                               const struct wn_direct_frame *, const uint8_t **, size_t *);

/* One caller-budgeted outgoing message; no recovery replay. Queue returns -2
 * when busy. A prepared frame borrows storage until accepted or suspended. */
struct wn_direct_datagram_sender {
    uint8_t *storage;
    size_t capacity, total, offset, pending_size;
    uint32_t flow, alias;
    uint64_t generation, last_id;
    bool active, pending;
};
int wn_direct_datagram_sender_init(struct wn_direct_datagram_sender *, uint32_t, uint8_t *, size_t);
int wn_direct_datagram_sender_bind(struct wn_direct_datagram_sender *, uint64_t, uint32_t);
void wn_direct_datagram_sender_suspend(struct wn_direct_datagram_sender *);
int wn_direct_datagram_queue(struct wn_direct_datagram_sender *, const uint8_t *, size_t);
int wn_direct_datagram_prepare(struct wn_direct_datagram_sender *, struct wn_direct_frame *);
/* Successful queue COPY, not peer ACK. Token fences delayed/double callbacks. */
int wn_direct_datagram_accepted(struct wn_direct_datagram_sender *, uint64_t generation,
                                uint64_t id, uint16_t offset);
