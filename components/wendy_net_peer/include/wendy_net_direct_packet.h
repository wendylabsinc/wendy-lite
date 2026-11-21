#pragma once
#include "wendy_net_direct_datagram.h"
#include "wendy_net_direct_socket.h"
/* Caller-reserved UDP slot, separate from reliable slabs. Three capacity-sized
 * buffers hold outgoing, assembling and completed messages. Dynamic slots reserve
 * all three buffers before OPEN succeeds; idle slots own only metadata.
 * The slot and storage must outlive their flow manager. */
struct wn_direct_packet {
    struct wn_direct_datagram_sender tx;
    struct wn_direct_datagram rx;
    uint8_t *storage;
    void *(*allocate)(size_t);
    void (*release)(void *);
    size_t capacity, ready_size;
    bool used, ready, promoted;
    uint8_t header_in[2], header_out[2], header_used, read_wait, write_wait;
    size_t wanted, received, sent;
};
int wn_direct_packet_init(struct wn_direct_packet *, uint8_t *, size_t storage_size);
int wn_direct_packet_init_dynamic(struct wn_direct_packet *, size_t maximum,
                                  void *(*allocate)(size_t), void (*release)(void *));
int wn_direct_packet_open(struct wn_direct_packet *, uint32_t flow, size_t maximum,
                          uint64_t generation, uint32_t alias);
int wn_direct_packet_bind(struct wn_direct_packet *, uint64_t generation, uint32_t alias);
void wn_direct_packet_suspend(struct wn_direct_packet *);
void wn_direct_packet_close(struct wn_direct_packet *);
int wn_direct_packet_poll(struct wn_direct_packet *, struct wn_direct_socket *);
int wn_direct_packet_receive(struct wn_direct_packet *, uint64_t generation,
                             const struct wn_direct_frame *);

struct wn_direct_upper;
/* After committed promotion and old worker fencing. Upper TLS retains the
 * existing big-endian uint16 length prefix, no direct ACK/DATA metadata. */
int wn_direct_packet_promote(struct wn_direct_packet *);
int wn_direct_packet_upper_poll(struct wn_direct_packet *, const struct wn_direct_upper *);

/* Actor-owned native message endpoint, e.g. a guest queue. read matches socket
 * datagram_read (1=message,2=drop,0=retry,-1=terminal); write copies the whole
 * message before returning 1, returns 0 for backpressure or -1 for retired owner.
 * pending must report actual local progress, never merely a queued blocked RX.
 * close disposes the endpoint only after successful ownership transfer. */
struct wn_direct_packet_io {
    void *context;
    int (*read)(void *, uint8_t *, size_t, size_t *);
    int (*write)(void *, const uint8_t *, size_t);
    void (*close)(void *);
    bool (*pending)(void *);
};
int wn_direct_packet_poll_io(struct wn_direct_packet *, const struct wn_direct_packet_io *);
