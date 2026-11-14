/* SPDX-License-Identifier: Apache-2.0
 * Reliable ordered byte streams over unreliable datagrams (ESP-NOW unicast).
 * Sans-I/O and single-owner: the caller serializes every call, supplies time
 * and a nonblocking datagram send. No OS, radio, clock or SDK dependency.
 * This is an untrusted transport. Wendy Net runs its ordinary mutual TLS
 * above it; nothing in a frame or advertisement grants identity or authority.
 */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* Every mesh datagram starts with this prefix so a shared ESP-NOW receiver
 * can tell it from application frames. */
#define WNES_MAGIC "WNEN"
#define WNES_VERSION 1
#define WNES_HEADER 24
#define WNES_FRAME_MIN 128
#define WNES_FRAME_MAX 1470 /* ESP_NOW_MAX_DATA_LEN_V2 */
#define WNES_WINDOW_MAX 16
enum { WNES_ADVERT = 1, WNES_SYN, WNES_SYNACK, WNES_DATA, WNES_ACK, WNES_FIN, WNES_RST };

/* Broadcast discovery hint: prefix, flags and the existing 46-byte presence
 * record (tenant, device, mesh hash). Dial planning only. */
#define WNES_ADVERT_SIZE 53
#define WNES_ACCEPTING 1  /* Has room for a mesh link. */
#define WNES_TIME_RELAY 2 /* Can forward a signed-time exchange to the timestamp authority. */
/* What a stream is for, named by the connecting side. At most eight kinds. */
enum { WNES_MESH, WNES_TIME };
int wnes_advert_write(const uint8_t tenant[16], const uint8_t device[16], const uint8_t mesh[8],
                      uint8_t flags, uint8_t out[WNES_ADVERT_SIZE]);
bool wnes_advert_read(const uint8_t tenant[16], const uint8_t mesh[8], const void *frame,
                      size_t size, uint8_t device[16], uint8_t *flags);

struct wnes_config {
    uint16_t frame_bytes; /* Whole datagram including WNES_HEADER. */
    uint8_t window;       /* Buffered segments per direction per stream. */
    uint8_t backlog;      /* Incoming streams not yet taken by the owner. */
    unsigned retries;     /* Consecutive unanswered timer expiries before failure. */
    int64_t rto_us, rto_max_us, ack_delay_us, idle_us, connect_us, linger_us;
    void *(*alloc)(size_t);
    void (*free)(void *);
    /* Nonblocking. Nonzero means not sent now (radio busy); it is retried. */
    int (*send)(void *context, const uint8_t mac[6], const void *frame, size_t size);
    uint32_t (*random)(void); /* Stream identifiers only, never key material. */
    void *context;
};
/* Timing and window defaults; the caller fills callbacks and may tune. */
void wnes_defaults(struct wnes_config *);

struct wnes;
struct wnes_conn;
/* At most max_streams streams, including connecting and closing ones. Idle
 * streams own no segment buffers; each holds at most 2*window segments. */
struct wnes *wnes_open(const struct wnes_config *, unsigned max_streams);
void wnes_close(struct wnes *);
/* Admission gate for new incoming streams: one bit per service, e.g.
 * 1 << WNES_MESH. Everything is refused by default. */
void wnes_accepting(struct wnes *, uint8_t services);
/* Starts connecting. Read/write report WANT until established, -1 on failure. */
struct wnes_conn *wnes_connect(struct wnes *, const uint8_t mac[6], uint8_t service,
                               int64_t now_us);
/* An established incoming stream, once. The peer address is a hint only. */
struct wnes_conn *wnes_accept(struct wnes *, uint8_t mac[6], uint8_t *service);
/* A received datagram that starts with WNES_MAGIC and is not an advert. */
void wnes_input(struct wnes *, const uint8_t mac[6], const void *frame, size_t size,
                int64_t now_us);
/* Runs timers and transmits what the windows allow. Returns the next time it
 * needs to run without new input (INT64_MAX when idle). Idempotent. */
int64_t wnes_tick(struct wnes *, int64_t now_us);
/* Positive progress, 0 EOF (peer closed after all its data), -2 WANT_READ,
 * -3 WANT_WRITE, -1 failed. Same contract as struct wnc_io. */
ssize_t wnes_read(void *conn, void *, size_t);
ssize_t wnes_write(void *conn, const void *, size_t);
/* Everything written has been acknowledged by the peer's stream layer. */
bool wnes_drained(const struct wnes_conn *);
/* The owner is done. Queued data is still delivered for linger_us, then the
 * peer sees EOF; the stream frees itself. The pointer is invalid afterwards. */
void wnes_release(struct wnes_conn *, int64_t now_us);
/* True while any stream to this address exists (radio peer-table upkeep). */
bool wnes_uses(const struct wnes *, const uint8_t mac[6]);
/* Segment buffers currently held and their high-water mark. */
unsigned wnes_segments(const struct wnes *, unsigned *peak);
