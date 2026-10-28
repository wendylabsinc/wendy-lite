#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Register networking host functions with the WASM runtime.
 */
int wendy_net_export_init(void);

/**
 * Close all guest-owned async networking resources and clear pending events.
 * Called when a WASM guest stops or is replaced.
 */
void wendy_net_guest_reset(void);

/** Open a loopback connection to a TCP listener owned by the current guest.
 * Used after native Wendy Net app TLS admission. Returns an owned nonblocking
 * socket or -1; stopping/replacing the guest removes its listeners normally.
 */
int wendy_net_guest_service_connect(uint16_t port);
int wendy_net_guest_datagram_connect(uint16_t port,int *owner);
int wendy_net_guest_datagram_owner(uint16_t port);
int wendy_net_guest_listener_owner(uint16_t port,bool datagram);
bool wendy_net_mesh_socket_live(int handle);
unsigned wendy_net_guest_datagram_capacity(void);

/* Native app TLS endpoint bridge. A successful delivery (1) consumes *packet
 * and clears it; 0 applies backpressure, -1 means the listener has retired.
 * Association is a guest socket handle, created on the first packet and
 * recreated after the guest closes it while retaining its listener. */
int wendy_net_guest_datagram_deliver(int owner,int *association,uint8_t **packet,size_t size,unsigned maximum);
/* Owned variants retain the packet's destructor until guest drain/reset or
 * explicit mesh shutdown. NULL means ordinary free. The destructor runs under
 * the networking lock: it must not block or reenter guest networking. Failed
 * or backpressured delivery retains both packet and destructor at the caller. */
typedef void (*wendy_net_packet_release_fn)(void *);
int wendy_net_guest_datagram_deliver_owned(int owner,int *association,uint8_t **packet,
    size_t size,unsigned maximum,wendy_net_packet_release_fn release);
/* Take a queued guest reply without copying it. Caller owns/frees the packet;
 * completion releases write backpressure only after the TLS frame is sent.
 * Handles are checked again on completion, including after guest reset. */
int wendy_net_guest_datagram_take(int association,uint8_t **packet,size_t *size);
void wendy_net_guest_datagram_sent(int association);
void wendy_net_guest_datagram_closed(int association);
/* Complete an outgoing authenticated datagram connection without an internal
 * loopback fd, then transfer its received packets with the same ownership rule. */
int wendy_net_mesh_datagram_connected(int handle,unsigned maximum);
int wendy_net_mesh_datagram_receive(int handle,uint8_t **packet,size_t size);
int wendy_net_mesh_datagram_receive_owned(int handle,uint8_t **packet,size_t size,
    wendy_net_packet_release_fn release);
/* After mesh flows stop, drop only their transferred native RX datagrams,
 * including packets retained on closed sockets for a guest that has not read.
 * Ordinary LAN RX, guest TX, listeners and other app buffers are untouched. */
void wendy_net_mesh_discard_pending_datagrams(void);

/* Native mesh transport adapter for the existing async guest TCP/UDP API.
 * begin returns 0 for ordinary DNS, 1 when it owns an async request, or -1
 * when a mesh request cannot start. It must copy host before returning.
 * complete consumes fd (or -1 on failure), including after guest reset. */
typedef int (*wendy_net_mesh_begin_fn)(int handle, const char *host, uint16_t port,bool datagram);
void wendy_net_set_mesh_connector(wendy_net_mesh_begin_fn begin);
/* Same recognized-name convention as begin; fills IPv6 bytes on success. */
typedef int (*wendy_net_mesh_resolve_fn)(const char *,uint8_t address[16]);
void wendy_net_set_mesh_resolver(wendy_net_mesh_resolve_fn);
int wendy_net_mesh_connected(int handle, int fd);
/* Actor-owned signed service catalogue. Operation0=browse,1=register,
 * 2=withdraw,3=browse endpoint summaries. Callback copies input and retains no
 * guest pointer. Endpoint summaries survive capacity eviction, include
 * detailsAvailable, and omit TXT/instance/full signed body. */
typedef int (*wendy_net_service_fn)(unsigned,const void *,size_t,char *,size_t);
void wendy_net_set_service_catalog(wendy_net_service_fn);
/* Zero while OFF; each replacement catalogue has a new nonzero incarnation.
 * The getter allocates nothing. A nonzero value does not promise a live route;
 * registration still returns temporary unavailability until the actor is ready. */
uint32_t wendy_net_service_epoch(void);

#ifdef __cplusplus
}
#endif

/* Returns a nonblocking loopback fd; caller completes connect via readiness. */
int wendy_net_guest_service_begin(uint16_t port);
