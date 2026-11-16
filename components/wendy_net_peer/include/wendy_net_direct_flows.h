#pragma once
#include "wendy_net_direct_open.h"
#include "wendy_net_direct_lane.h"
#include "wendy_net_direct_socket.h"
#include "wendy_net_direct_packet.h"
#include "wendy_net_direct_recovery_plan.h"

enum wn_direct_result {
    WN_DIRECT_DENIED = 1,
    WN_DIRECT_NO_CAPACITY,
    WN_DIRECT_CANCELLED,
    WN_DIRECT_IO,
    WN_DIRECT_UNSUPPORTED
};
struct wn_direct_request {
    uint8_t service;
    uint16_t port, datagram_size;
};
/* Actor-owned, already authenticated and per-flow bound upper TLS stream.
 * read/write return bytes, -2/-3 for retry, negative for fatal; read 0 is EOF.
 * write accepts/copies bytes before returning; no borrowed payload may escape.
 * shutdown_write returns 0 on success, -2/-3 retry, negative fatal. */
struct wn_direct_upper {
    void *context;
    int (*read)(void *, uint8_t *, size_t);
    int (*write)(void *, const uint8_t *, size_t);
    int (*shutdown_write)(void *);
    void (*close)(void *);
    /* Optional root-actor readiness hooks. pending reports decrypted bytes already
     * buffered by TLS, which need another turn without a socket readiness edge. */
    int (*fd)(void *);
    bool (*pending)(void *);
};
struct wn_direct_promoted_binding;
struct wn_direct_flow {
    struct wn_direct_open_entry open;
    struct wn_direct_promoted_binding *binding;
    struct wn_direct_packet *packet;
    struct wn_direct_packet_io packet_io;
    uint32_t id;
    struct wn_direct_request request;
    struct wn_direct_sender sender;
    struct wn_direct_receiver receiver;
    struct wn_direct_lane lane;
    struct wn_direct_socket socket;
    struct wn_direct_upper upper;
    size_t upper_pending;
    bool promoted, upper_write_closed;
    uint8_t upper_read_wait, upper_write_wait; /* 1=read,2=write;0=normal direction */
    uint16_t reset_code;
    bool has_lane, reset, open_pending, result_pending, reset_pending, close_pending;
};
/* All metadata/payload storage is caller-owned and must be charged to the
 * network ledger. Two independent namespaces have slots entries each. The
 * flows/expected/retired arrays each have 2*slots elements. No heap allocation.
 * Actor owns every API; asynchronous completions use never-reused flow IDs. */
struct wn_direct_flows {
    bool datagram_limit_pending, peer_datagram_known;
    uint16_t datagram_limit, peer_datagram_limit;
    struct wn_direct_opens opens[2];
    struct wn_direct_flow *flows;
    struct wn_direct_recovery_record *expected;
    uint32_t *retired;
    struct wn_direct_pool *tx, *rx;
    struct wn_direct_packet *packets;
    size_t packet_count;
    uint64_t packet_generation;
    uint16_t slots, count, expected_count, retired_count;
    uint8_t role;
    uint32_t alias, next_id, cursor;
    uint64_t window, initial;
    bool closed, credit_pending, pending_lane, upper_control;
    bool idle_sent, peer_idle;
    struct wn_direct_frame pending;
    uint8_t scratch[WN_DIRECT_MAX_DATA];
};
/* Actor-only local write capacity. Preserves other admitted senders' minimum
 * replay share; socket and native adapters must use it before accepting data. */
uint64_t wn_direct_flows_send_capacity(const struct wn_direct_flows *,
                                       const struct wn_direct_flow *);
int wn_direct_request_digest(struct wn_direct_request, uint8_t out[32]);
int wn_direct_flows_init(struct wn_direct_flows *, uint8_t role, uint16_t slots,
                         struct wn_direct_flow *,
                         struct wn_direct_recovery_record *expected, uint32_t *retired,
                         struct wn_direct_pool *tx, struct wn_direct_pool *rx, uint64_t window,
                         uint64_t initial);
/* Explicit opt-in before any attachment/OPEN; default UDP is unsupported.
 * Each initialized slot has independent caller-charged UDP storage. */
int wn_direct_flows_enable_datagrams(struct wn_direct_flows *, struct wn_direct_packet *, size_t);
/* Actor-only local capacity policy, set before the first attachment.
 * Zero advertises no new UDP. Existing requests stay immutable. */
int wn_direct_flows_set_datagram_limit(struct wn_direct_flows *, uint16_t);
int wn_direct_flows_bind(struct wn_direct_flows *, uint32_t alias);
void wn_direct_flows_suspend(struct wn_direct_flows *);
void wn_direct_flows_close(struct wn_direct_flows *);
int wn_direct_flows_begin(struct wn_direct_flows *, struct wn_direct_request, int64_t now,
                          uint32_t *id);
/* CompleteIncoming must precede binding the successfully authorized local fd,
 * within the same actor turn and before emitting OPEN_RESULT. Late completion
 * of a reset/retired flow fails; caller must close the unclaimed fd. */
int wn_direct_flows_complete(struct wn_direct_flows *, uint32_t id, uint16_t result);
/* Takes ownership of fd only on success; only after a successful OPEN result. */
int wn_direct_flows_socket(struct wn_direct_flows *, uint32_t id, int fd);
int wn_direct_flows_reset(struct wn_direct_flows *, uint32_t id, uint16_t code);
/* Nonblocking local socket service continues while carrier is suspended, but
 * caller freezes it during snapshot/commit. Errors reset only that flow. */
int wn_direct_flows_poll(struct wn_direct_flows *);
/* fresh_id != 0 is the sole authorization/backend-open event. Pending, duplicate,
 * cancelled or refused OPENs never request another backend. */
int wn_direct_flows_receive(struct wn_direct_flows *, const struct wn_direct_frame *, int64_t now,
                            uint32_t *fresh_id);
/* 1=ready,0=idle,negative=error. Stable output until writer COPY is accepted. */
int wn_direct_flows_prepare(struct wn_direct_flows *, int64_t now, struct wn_direct_frame *);
int wn_direct_flows_accepted(struct wn_direct_flows *);
struct wn_direct_flow *wn_direct_flows_find(struct wn_direct_flows *, uint32_t id);
int wn_direct_flows_snapshot(struct wn_direct_flows *, struct wn_direct_recovery_record *,
                             size_t capacity, struct wn_direct_recovery_view *);
/* Scratch local records require 2*slots; plan capacity >= local+remote count.
 * Full validation precedes mutations. Any apply failure closes the session. */
int wn_direct_flows_recover(struct wn_direct_flows *, const struct wn_direct_recovery_view *,
                            int64_t now, struct wn_direct_recovery_record *local,
                            size_t local_capacity, struct wn_direct_recovery_step *plan,
                            size_t plan_capacity);
bool wn_direct_flows_quiescent(const struct wn_direct_flows *);
/* Actor must join pending work and drain copied control output before close. */
bool wn_direct_flows_retirement_ready(const struct wn_direct_flows *);

/* Call only after committed promotion reconciliation, with old lane fenced.
 * Keeps only retained OPEN/result/reset/close metadata; no DATA/STATE/FIN and
 * no new OPENs outside the committed union. Promotion is one-way. */
int wn_direct_flows_bind_promoted(struct wn_direct_flows *, uint32_t alias);
/* Transfers upper ownership on success only, following per-flow binding.
 * Pending opens remain pending; caller must not reopen their backend. */
int wn_direct_flows_promote(struct wn_direct_flows *, uint32_t id, const struct wn_direct_upper *);

/* Transfers an authorized native UDP endpoint after successful OPEN. No local
 * fd is needed. On failure the caller retains ownership; close runs once on
 * reset/retirement. Mutually exclusive with flows_socket. */
int wn_direct_flows_packet_io(struct wn_direct_flows *, uint32_t,
                              const struct wn_direct_packet_io *);

/* OPEN metadata is read from the same retained flow record as its payload. */
int wn_direct_flows_open(struct wn_direct_flows *, uint32_t id, struct wn_direct_open_entry *);
