#ifndef WENDY_COM_LINK_H
#define WENDY_COM_LINK_H

#include "esp_tls.h"
#include "wendy_com_common.h"

// literals

#define WCOM_LINK_COUNT  4

// types

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

// agent side interface, abstracting platform entirely

void wcom_add_state_change_handler(struct wcom_state_change_handler *handler);
void wcom_remove_state_change_handler(struct wcom_state_change_handler *handler);

void wcom_recv(int link_id, struct wcom_rx_chunk *chunk);
void wcom_send(int link_id, struct wcom_tx_chunk *chunk);
void wcom_close(int link_id);

// connection provider interface, ESP-IDF-specific

int wcom_add_link(esp_tls_t *tls);
void wcom_remove_link(int link_id);

#endif
