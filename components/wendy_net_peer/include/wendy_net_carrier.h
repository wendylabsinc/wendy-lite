/* SPDX-License-Identifier: Apache-2.0
 * Single-owner nonblocking WendyOS stream framing. Callbacks never wait.
 */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#ifdef ESP_PLATFORM
#include "sdkconfig.h"
#endif
/* Sparse FIFO classes share one existing allocation ceiling. */
enum {WNC_ROUTE,WNC_METADATA,WNC_IP,WNC_CLASSES};
#define WNC_CLASS_RESERVE 1536U

enum
{
    WNC_INVALID = -1,
    WNC_LIMIT = -2,
    WNC_IO = -3,
    WNC_TIMEOUT = -4,
    WNC_CLOSED = -5,
    WNC_NOMEM = -6
};
struct wnc_frame;
struct wnc_io
{
    void *context;
    /* Positive progress,0 EOF,-2 WANT_READ,-3 WANT_WRITE,other error. */
    ssize_t (*read)(void *, void *, size_t);
    ssize_t (*write)(void *, const void *, size_t);
};
struct wnc_carrier
{
    struct wnc_io io;
    struct wnc_frame *head, *tail;
    struct wnc_frame *class_head[WNC_CLASSES],*class_tail[WNC_CLASSES];
    size_t class_bytes[WNC_CLASSES];
    unsigned class_frames[WNC_CLASSES],routing_limit;
    bool fair,last_routing,last_metadata;
    uint8_t *small, *body;
    size_t small_size, limit, control_limit, priority_reserve, queued, body_size, body_have;
    uint8_t header[5];
    unsigned header_have;
    bool rx_paused;
    int64_t rx_started, rx_progress;
    int64_t stall_timeout_us, frame_timeout_us;
};
struct wnc_timeout {bool writing;size_t offset,size;int64_t idle_us,age_us;};
/* Describe an expired partial frame without allocating or changing state. */
bool wnc_timeout_snapshot(const struct wnc_carrier *,int64_t,struct wnc_timeout *);
int wnc_init(struct wnc_carrier *, const struct wnc_io *, void *small,
             size_t small_size, size_t queue_limit, size_t control_limit);
void wnc_deinit(struct wnc_carrier *);
/* Enable on an empty carrier. At frame boundaries Babel alternates with
 * another eligible class; metadata and IP alternate independently. Preserve
 * one maximum datagram/whole fragmented IP's unused admission capacity in
 * each class, inside the existing total limit, never by allocating reserves.
 * A begun frame remains pinned. No I/O, timer or protocol changes. */
int wnc_fair_scheduler(struct wnc_carrier *,unsigned routing_frames);
/* Copies a complete frame; bounded sparse allocation, no I/O or reentrancy.
 * Control includes the usual inner4byte length; datagrams remain opaque. */
int wnc_enqueue(struct wnc_carrier *, const void *, size_t, bool control);
/* Legacy priority may overtake complete unstarted IP frames. Fair mode uses
 * distinct routing/metadata classes and admission reserves instead. A begun
 * frame remains pinned, including a zero-accepted-byte TLS WANT_WRITE retry.
 * priority_reserve bounds legacy ordinary IP occupancy. */
int wnc_enqueue_priority(struct wnc_carrier *,const void *,size_t,bool control);
/* All fragments of one IPv6 packet enter the queue atomically. On pressure,
 * no fragment is retained; callers may drop this IP packet and keep the
 * authenticated control stream. TCP retransmission remains end-to-end. */
int wnc_enqueue_packet(struct wnc_carrier *, const void *, size_t, uint32_t id);
/* Receive: zero consumed, positive retain/retry this frame, negative error. */
typedef int (*wnc_receive)(void *, const void *, size_t, bool control);
/* Service both directions once.1 progress,0 would block,negative error.
 * receive may enqueue replies; it must not call pump/deinit recursively.
 * A pending write keeps exactly the same pointer/length until TLS accepts it.
 * Partial frames default to5s without progress or30s total. Owners may raise
 * the two timeout fields for a constrained carrier; routing timers are separate. */
int wnc_pump(struct wnc_carrier *, int64_t monotonic_us, wnc_receive, void *);
