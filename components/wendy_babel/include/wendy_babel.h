/* SPDX-License-Identifier: Apache-2.0
 * Bounded native port of WendyOS go/babel. Single-owner, sans-I/O engine.
 * The caller owns authentication, time, durable history and atomic forwarding.
 */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#ifdef ESP_PLATFORM
#include "sdkconfig.h"
#endif

#ifndef WB_LINKS
#ifdef CONFIG_WENDY_NET_MAX_LINKS
#define WB_LINKS CONFIG_WENDY_NET_MAX_LINKS
#else
#define WB_LINKS 4
#endif
#endif
#ifndef WB_ROUTES
#if defined(ESP_PLATFORM) && CONFIG_WENDY_NET_CONSTRAINED_PROFILE
#define WB_ROUTES 32
#else
#define WB_ROUTES 128
#endif
#endif
#ifndef WB_CANDIDATES
#if defined(ESP_PLATFORM) && CONFIG_WENDY_NET_CONSTRAINED_PROFILE
#define WB_CANDIDATES 64
#else
#define WB_CANDIDATES 768
#endif
#endif
#ifndef WB_SOURCES
#if defined(ESP_PLATFORM) && CONFIG_WENDY_NET_CONSTRAINED_PROFILE
#define WB_SOURCES 64
#else
#define WB_SOURCES 512
#endif
#endif
#ifndef WB_REQUESTS
#if defined(ESP_PLATFORM) && CONFIG_WENDY_NET_CONSTRAINED_PROFILE
#define WB_REQUESTS 8
#else
#define WB_REQUESTS 64
#endif
#endif
#ifndef WB_MESSAGES
#if defined(ESP_PLATFORM) && CONFIG_WENDY_NET_CONSTRAINED_PROFILE
#define WB_MESSAGES 96
#else
/* A64-origin dump across six carriers needs more than256 queued TLVs.
 * This is a growth ceiling, not an allocated array. SRAM keeps96 above. */
#define WB_MESSAGES 1024
#endif
#endif
#define WB_INFINITY UINT16_MAX
#define WB_PACKET_MAX 1099
#define WB_HISTORY_MAX (40 + WB_SOURCES * 30 + WB_ROUTES * 18)

enum wb_status
{
    WB_OK = 0,
    WB_PENDING = 1,
    WB_INVALID = -1,
    WB_LIMIT = -2,
    WB_STOPPED = -3,
    WB_BUSY = -4
};
enum wb_type
{
    WB_ACK_REQUEST = 2,
    WB_ACK = 3,
    WB_HELLO = 4,
    WB_IHU = 5,
    WB_ROUTER = 6,
    WB_NEXT_HOP = 7,
    WB_UPDATE = 8,
    WB_REQUEST = 9,
    WB_SEQ_REQUEST = 10
};
/* IPv4 bytes occupy the first four positions, with the remaining bytes zero. */
struct wb_prefix
{
    uint8_t bytes[16], bits, family;
};
struct wb_message
{
    struct wb_prefix prefix;
    uint8_t address[16], address_family, type, hops;
    bool unicast, wildcard, via6;
    uint16_t seqno, metric, interval, opaque;
    uint64_t router;
};
struct wb_route
{
    struct wb_prefix prefix;
    uint8_t next_hop[16], next_family;
    uint64_t router, link;
    uint16_t seqno, metric;
    bool local, unreachable;
};
struct wb_link
{
    uint64_t id;
    uint8_t local[16], peer[16], ipv4[4];
    uint16_t cost, max_packet;
    uint32_t hello_ms;
};
struct wb_link_state
{
    struct wb_link config;
    uint64_t hello_expires[2], ihu_expires, next_hello, next_ihu, next_update, last_dump;
    uint16_t hello_rx[2], hello_seq, tx;
    bool hello_seen[2], dumped;
};
struct wb_candidate
{
    struct wb_route route;
    uint64_t expires;
    uint32_t interval_ms;
    uint16_t advertised;
    bool used, refresh_requested;
};
struct wb_source
{
    struct wb_prefix prefix;
    uint64_t router, expires;
    uint16_t seqno, metric;
    bool used;
};
struct wb_local
{
    struct wb_prefix prefix;
    uint16_t metric;
    bool used;
};
struct wb_drop
{
    struct wb_prefix prefix;
    uint64_t expires;
    bool used;
};
struct wb_request_state
{
    struct wb_message message;
    uint64_t targets[WB_LINKS], from, next, expires;
    uint8_t target_count, remaining;
    bool used;
};
struct wb_queued
{
    struct wb_message message;
    uint64_t link;
};
/* allow() is checked before candidate admission and at every selection. A TLS
 * neighbour alone does not authenticate the origin of a relayed route. */
struct wb_config
{
    uint64_t router, seed;
    uint16_t seqno;
    uint32_t hello_ms, update_ms, source_ms;
    bool ipv4_via_ipv6;
    /* Endpoint mode advertises local prefixes and maintains adjacency only. */
    bool local_only;
    bool (*allow)(void *context, uint64_t router, const struct wb_prefix *, uint16_t seqno);
    void *context;
    /* Optional allocator pair. Tables grow on demand within WB_* bounds.
     * allocate may return uninitialised memory; the engine clears it. */
    void *(*allocate)(void *memory_context, size_t bytes);
    void (*deallocate)(void *memory_context, void *memory);
    void *memory_context;
};
struct wb_counters
{
    uint64_t received, malformed, rejected, sent, queue_drops, allocation_failures;
};
struct wb_engine
{
    struct wb_config config;
    uint64_t now, rng, last_link, revision, pending, trigger_at;
    uint16_t seqno;
    uint8_t repeats;
    bool trigger, stopped, ready;
    struct wb_link_state *links;
    size_t links_capacity;
    struct wb_candidate *candidates;
    size_t candidates_capacity;
    struct wb_source *sources;
    size_t sources_capacity;
    struct wb_local *local;
    size_t local_capacity;
    struct wb_drop *drops;
    size_t drops_capacity;
    struct wb_request_state *requests;
    size_t requests_capacity;
    struct wb_route *routes, *before, *scratch;
    size_t routes_capacity, before_capacity, scratch_capacity;
    size_t allocated_bytes, peak_bytes;
    size_t route_count, before_count;
    struct wb_queued *messages;
    size_t messages_capacity;
    size_t message_count, message_cursor;
    struct wb_counters counters;
};

bool wb_prefix_valid(const struct wb_prefix *);
bool wb_prefix_equal(const struct wb_prefix *, const struct wb_prefix *);
void wb_prefix_mask(struct wb_prefix *);
/* Two-pass decode: malformed outer framing invokes no visitor. Prefix/router/
 * next-hop contexts are packet-local. Unknown mandatory sub-TLVs suppress a TLV. */
int wb_decode(const void *packet, size_t size, const uint8_t source[16],
              void (*visit)(void *, const struct wb_message *), void *context);
size_t wb_encode(const struct wb_message *, uint8_t *out, size_t capacity);
/* The first call requires a zero-initialised engine. Reinitialising releases
 * previous allocations. No tables are allocated until they are needed. */
int wb_init(struct wb_engine *, const struct wb_config *);
void wb_deinit(struct wb_engine *);
struct wb_memory
{
    size_t current, peak;
};
/* Requested bytes, including the engine and transient resize copies, excluding
 * platform allocator headers and caller task/I/O/storage buffers. */
struct wb_memory wb_memory(const struct wb_engine *);
int wb_tick(struct wb_engine *, uint64_t now_ms);
int wb_add_link(struct wb_engine *, uint64_t now_ms, const struct wb_link *);
int wb_remove_link(struct wb_engine *, uint64_t now_ms, uint64_t link);
int wb_set_cost(struct wb_engine *, uint64_t now_ms, uint64_t link, uint16_t cost);
int wb_originate(struct wb_engine *, uint64_t now_ms, const struct wb_prefix *, uint16_t metric);
int wb_withdraw(struct wb_engine *, uint64_t now_ms, const struct wb_prefix *);
int wb_receive(struct wb_engine *, uint64_t now_ms, uint64_t link, const void *, size_t size);
/* Apply ALL routes, persist history, and then commit. A failed commit stops the
 * engine permanently. On WB_STOPPED the caller must withdraw all forwarding.
 * No event is accepted with pending forwarding or output. */
int wb_commit(struct wb_engine *, uint64_t revision, bool success);
/* Return one complete Babel payload; 0 when drained, negative on API misuse.
 * Persist history even when an event did not change the forwarding snapshot. */
int wb_next_packet(struct wb_engine *, uint64_t *link, uint8_t *out, size_t capacity);
uint64_t wb_next_deadline(const struct wb_engine *); /* UINT64_MAX if none */
const struct wb_route *wb_lookup(const struct wb_engine *, const struct wb_prefix *host);
/* Binary checkpoint, explicit byte order, fixed bounds. No pointers/ABI padding.
 * Save before exporting packets; restore retains suppression and feasibility,
 * never live links/routes. The caller provides atomic storage and integrity. */
/* out=NULL queries exact required bytes without allocation or mutation. */
int wb_save(const struct wb_engine *, uint8_t *out, size_t capacity);
/* Like init, restore requires a zero-initialised or previously initialised engine. */
int wb_restore(struct wb_engine *, const struct wb_config *, const uint8_t *, size_t size);
