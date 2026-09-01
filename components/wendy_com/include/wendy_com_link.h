#ifndef WENDY_COM_LINK_H
#define WENDY_COM_LINK_H

#include "wendy_com_uart.h"
#include "wendy_com_common.h"

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

// base functions

void wcom_core_init(void);
void wcom_core_exec(struct wcom_operation *op);
bool wcom_is_com_thread(void);

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
// transport supplies an eventfd that becomes readable whenever readiness may
// have changed; wcom drains it and then asks can_read()/can_write() for the
// truth, because readiness is level state and a signal that races the sample
// must not be lost.
//
// A vtable rather than another link type in the union: it is what lets such a
// transport depend on wendy_com without wendy_com having to depend back on it.

#define WCOM_STREAM_ERR_UNKNOWN     -1
#define WCOM_STREAM_ERR_WANT_READ   -2
#define WCOM_STREAM_ERR_WANT_WRITE  -3

struct wcom_stream_ops {
    /// Byte count, 0 at end of stream, or a WCOM_STREAM_ERR_*.
    ssize_t (*read)(void *ctx, void *buf, size_t len);
    /// Byte count consumed, which may be short, or a WCOM_STREAM_ERR_*.
    ssize_t (*write)(void *ctx, const void *buf, size_t len);
    /// Readable whenever readiness may have changed. Non-blocking.
    int     (*wakeup_fd)(void *ctx);
    bool    (*can_read)(void *ctx);
    bool    (*can_write)(void *ctx);
};

int wcom_add_stream_link(const struct wcom_stream_ops *ops, void *ctx);

// connection provider interface, ESP-IDF-specific

int wcom_add_tls_link(esp_tls_t *tls);
int wcom_add_uart_link(wendy_com_uart_t *uart);
void wcom_remove_link(int link_id);

#endif
