#pragma once
#include "wendy_net_direct_control.h"
#include "wendy_net_direct_transaction.h"
/* Session owner provides authenticated local identity/role, independently
 * generated nonce, frozen immutable local snapshot, and pre-reserved remote
 * storage. No allocation or blocking I/O occurs in this driver.
 * Initial participant ID/capability admission and alias uniqueness must be
 * authorized by that owner before init; a decoded OFFER is not authority. */
struct wn_direct_exchange_config {
    struct wn_direct_session_binding binding;
    struct wn_direct_generation *gate;
    uint64_t token;
    uint8_t nonce[16];
    struct wn_direct_recovery_view local;
    struct wn_direct_recovery_record *remote_records;
    size_t remote_capacity;
    wn_direct_exporter exporter;
    void *export_arg;
    int (*apply)(void *);
    void *apply_arg;
};
enum wn_direct_exchange_phase {
    WN_DX_WAIT_VIEW,
    WN_DX_WAIT_RECORDS,
    WN_DX_WAIT_READY,
    WN_DX_WAIT_COMMIT,
    WN_DX_WAIT_ACK,
    WN_DX_ACTIVE,
    WN_DX_FAILED
};
struct wn_direct_exchange {
    struct wn_direct_exchange_config cfg;
    struct wn_direct_attachment attachment;
    struct wn_direct_recovery_view remote;
    struct wn_direct_transaction tx;
    enum wn_direct_exchange_phase phase;
    size_t remote_count, send_index;
    uint8_t send_kind;
    bool create;
};
/* Initialize fresh storage only. All supplied storage remains valid until lost
 * or disposal after no queued record/callback references this attempt. */
int wn_direct_exchange_coordinator(struct wn_direct_exchange *,
                                   const struct wn_direct_exchange_config *, uint32_t alias,
                                   uint64_t generation, enum wn_direct_mode, bool create);
int wn_direct_exchange_participant(struct wn_direct_exchange *,
                                   const struct wn_direct_exchange_config *,
                                   const struct wn_direct_control *offer);
/* next returns 1 record, 0 idle, -1 invalid. Stable under backpressure.
 * accepted follows ordered writer COPY ownership, before receiving peer input;
 * it must not wait for TLS write completion. */
int wn_direct_exchange_next(const struct wn_direct_exchange *, struct wn_direct_control *);
int wn_direct_exchange_accepted(struct wn_direct_exchange *);
int wn_direct_exchange_receive(struct wn_direct_exchange *, const struct wn_direct_control *);
bool wn_direct_exchange_active(const struct wn_direct_exchange *);
/* Candidate connection death, never a promoted underlay interruption. */
void wn_direct_exchange_lost(struct wn_direct_exchange *);
