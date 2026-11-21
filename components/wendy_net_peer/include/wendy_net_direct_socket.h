#pragma once
#include "wendy_net_direct_buffer.h"
/* Actor-owned adapter for a retained local application socket. Carrier changes
 * never close this fd. The session owns authorization, framing, credit grants,
 * generation fencing and final disposal of the descriptor and buffers. */
struct wn_direct_socket {
    int fd;
    bool read_eof, write_shutdown;
};
/* Makes only this local socket nonblocking. Does not take ownership on failure. */
int wn_direct_socket_init(struct wn_direct_socket *, int fd);
/* Returns 1 for progress, 0 for backpressure/no work, -1 for terminal error.
 * TX reserves shared-slab capacity BEFORE reading application bytes. RX releases
 * only the prefix accepted by the local socket. No private replay window. */
int wn_direct_socket_read(struct wn_direct_socket *, struct wn_direct_sender *, uint64_t window);
int wn_direct_socket_write(struct wn_direct_socket *, struct wn_direct_receiver *);

/* Datagram adapters for connected, authorized local UDP sockets. The caller
 * owns one bounded message buffer; no stream EOF/half-close semantics apply.
 * read: 1=whole message (including empty), 2=oversize message consumed/dropped,
 * 0=no work, -1=fatal. Never deliver a truncated prefix as a datagram.
 * write: 1=whole message accepted, 0=retry, -1=fatal. The caller chooses its
 * bounded queue/drop policy; a partial write must never be retried as a suffix. */
int wn_direct_socket_datagram_read(struct wn_direct_socket *, uint8_t *, size_t, size_t *);
int wn_direct_socket_datagram_write(struct wn_direct_socket *, const uint8_t *, size_t);
