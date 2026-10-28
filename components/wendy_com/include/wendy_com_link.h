#ifndef WENDY_COM_LINK_H
#define WENDY_COM_LINK_H

#include "wendy_com_uart.h"
#include "wendy_com_common.h"

#ifdef __cplusplus
extern "C" {
#endif

// literals

#define WCOM_LINK_COUNT  4

// types

typedef struct esp_tls esp_tls_t;

enum wcom_link_state {
    WCOM_LINK_STATE_UNDEFINED = 0,
    WCOM_LINK_STATE_CONNECTED,
    WCOM_LINK_STATE_DISCONNECTED,
    WCOM_LINK_STATE_ERROR,
};

/* Transport authentication fixes this permission before any link callbacks.
 * Every protocol channel on the link inherits it for its entire lifetime. */
enum wcom_link_permission {
    WCOM_LINK_PERMISSION_NONE = 0,
    WCOM_LINK_PERMISSION_FULL,
    WCOM_LINK_PERMISSION_SENSOR_ONLY,
};

struct wcom_rx_chunk;
struct wcom_tx_chunk;

typedef void (*wcom_rx_done_handler_t)(int link_id, const struct wcom_rx_chunk *chunk, bool success);
typedef void (*wcom_tx_done_handler_t)(int link_id, const struct wcom_tx_chunk *chunk, bool success);

struct wcom_rx_chunk {
    void *data;
    size_t size;
    wcom_rx_done_handler_t done_handler;
    struct wcom_rx_chunk *next;
};

struct wcom_tx_chunk {
    const void *data;
    size_t size;
    wcom_tx_done_handler_t done_handler;
    struct wcom_tx_chunk *next;
};

struct wcom_state_change_handler {
    void(* func)(struct wcom_state_change_handler *op, int link_id, enum wcom_link_state state);
    struct wcom_state_change_handler *next;
};

enum wcom_interruption_reason {
    WCOM_INTERRUPTION_CONNECTION_CLOSED = 0,
    WCOM_INTERRUPTION_CONNECTION_ERROR,
};

/// Called once, on the com thread, when the link it was given for is closed or
/// fails, after the state change handlers have run. The link still exists at
/// that point: its owner is expected to call wcom_remove_link() from here,
/// before releasing the underlying transport.
typedef void (*wcom_interruption_handler_t)(int link_id, enum wcom_interruption_reason reason);

// base functions

void wcom_core_init(void);

// Queue op for execution on the com task, handing ownership of *op over to it.
// Thread-safe and callable from any task — including the com task itself, and
// from inside another operation's func — but not from an ISR, since it writes
// to an eventfd.
//
// Ownership comes back to the caller the instant the com task enters func():
// from that point the queue never reads or writes *op again, not even to find
// the operation to run next. So func() may re-queue the node or free it
// outright, and so may any other task once func() has started. wendy_server
// relies on the free, wendy_com_stdio and wendy_com_stdio_pump on the re-queue.
//
// Until then the node belongs to the queue and the caller must not write any
// part of it: not `next`, rewritten on the push and again when the queue is
// drained; not `func`, read at call time; nor a payload embedded alongside it.
// A producer reusing a single static node must therefore ensure it is never
// queued twice before the previous func() has started — the queue does not
// detect a double push, it corrupts the list.
void wcom_core_exec(struct wcom_operation *op);

bool wcom_is_com_thread(void);
/* Permanent baseline com-task eventfd, or -1 before that task starts. Providers
 * may share it for level readiness; they must never close or drain this fd.
 * Wake after publishing readiness changes. Task callers only, not ISR. */
int wcom_core_wakeup_fd(void);
void wcom_core_wake(void);

const char *wcom_link_state_to_str(enum wcom_link_state state);

// agent side interface, abstracting platform entirely

void wcom_add_state_change_handler(struct wcom_state_change_handler *handler);
void wcom_remove_state_change_handler(struct wcom_state_change_handler *handler);

void wcom_recv(int link_id, struct wcom_rx_chunk *chunk);
void wcom_send(int link_id, struct wcom_tx_chunk *chunk);
void wcom_close(int link_id);

// stream link provider interface, transport-agnostic
//
// For a transport that has no file descriptor of its own — a BLE L2CAP
// channel, say, which is a stack callback — these replace the fd. The
// transport supplies a readiness eventfd (or shares wcom_core_wakeup_fd())
// that becomes readable whenever readiness may
// have changed; wcom drains it and then asks can_read()/can_write() for the
// truth, because readiness is level state and a signal that races the sample
// must not be lost.
//
// A vtable rather than another link type in the union: it is what lets such a
// transport depend on wendy_com without wendy_com having to depend back on it.

#define WCOM_STREAM_ERR_UNKNOWN     -1
#define WCOM_STREAM_ERR_WANT_READ   -2
#define WCOM_STREAM_ERR_WANT_WRITE  -3

/* Captured by the agent while CONNECTED, before any protocol body allocation.
 * The provider keeps context valid through all state-change callbacks, including
 * UNDEFINED removal. These hooks own only the agent protocol buffer, never app
 * or command-delegate allocations. Both absent retains ordinary libc behavior. */
struct wcom_link_buffer_allocator {
    void *context;
    void *(*allocate)(void *context, size_t size);
    void (*release)(void *context, void *buffer);
};
bool wcom_link_get_buffer_allocator(int link_id,
                                    struct wcom_link_buffer_allocator *out);

struct wcom_stream_ops {
    /// Byte count, 0 at end of stream, or a WCOM_STREAM_ERR_*.
    ssize_t (*read)(void *ctx, void *buf, size_t len);
    /// Byte count consumed, which may be short, or a WCOM_STREAM_ERR_*.
    ssize_t (*write)(void *ctx, const void *buf, size_t len);
    /// Readable whenever readiness may have changed. Non-blocking.
    int     (*wakeup_fd)(void *ctx);
    bool    (*can_read)(void *ctx);
    bool    (*can_write)(void *ctx);
    /* Optional paired hooks, using the same transport context. */
    void *(*allocate_buffer)(void *ctx, size_t size);
    void (*free_buffer)(void *ctx, void *buffer);
};

int wcom_add_stream_link(const struct wcom_stream_ops *ops, void *ctx,
                         wcom_interruption_handler_t interruption_handler);
/* Routed eventfd-backed byte stream with its authenticated permission fixed
 * before CONNECTED callbacks; retains the normal four-slot bound and 45s
 * write-progress allowance. No TLS is added by WendyCom itself. */
int wcom_add_routed_stream_link_with_permission(const struct wcom_stream_ops *ops, void *ctx,
                         wcom_interruption_handler_t interruption_handler,
                         enum wcom_link_permission permission);
// Socket-backed custom TLS transport. wakeup_fd returns the transport socket,
// selected but never drained as eventfd. can_read/can_write are not used.
int wcom_add_socket_link(const struct wcom_stream_ops *ops, void *ctx,
                         wcom_interruption_handler_t interruption_handler);
/* Authenticated network transports pass the peer's permission explicitly.
 * Constructors without a permission argument retain full access. NONE and
 * unknown values are rejected; a link's permission cannot be changed. */
int wcom_add_socket_link_with_permission(const struct wcom_stream_ops *ops, void *ctx,
                         wcom_interruption_handler_t interruption_handler,
                         enum wcom_link_permission permission);
/* Routed mesh TCP: allow 45s without write progress for carrier/route recovery.
 * All queue and buffer limits remain identical; ordinary transports use 15s. */
int wcom_add_routed_socket_link_with_permission(const struct wcom_stream_ops *ops, void *ctx,
                         wcom_interruption_handler_t interruption_handler,
                         enum wcom_link_permission permission);
bool wcom_link_is_local(int link_id);
enum wcom_link_permission wcom_link_get_permission(int link_id);
int wcom_add_tls_link(esp_tls_t *tls, wcom_interruption_handler_t interruption_handler);
int wcom_add_tls_link_with_permission(esp_tls_t *tls,
                         wcom_interruption_handler_t interruption_handler,
                         enum wcom_link_permission permission);
int wcom_add_uart_link(wendy_com_uart_t *uart, wcom_interruption_handler_t interruption_handler);
void wcom_remove_link(int link_id);

#ifdef __cplusplus
}
#endif

#endif
