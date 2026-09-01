#ifndef WENDY_BLE_L2CAP_H
#define WENDY_BLE_L2CAP_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#include "esp_err.h"
#include "freertos/FreeRTOS.h"

/// The device serves one L2CAP session at a time, so this whole module is a
/// singleton rather than a handle-based API. A second connection attempt is
/// rejected at COC_ACCEPT.

#define WBLE_ERR_UNKNOWN     -1
#define WBLE_ERR_WANT_READ   -2
#define WBLE_ERR_WANT_WRITE  -3

/// Create the SDU pool and the L2CAP server. Call once, after the NimBLE host
/// is running.
esp_err_t wble_l2cap_init(void);

/// Block until a peer opens the channel. Returns false on timeout.
bool wble_l2cap_wait_session(TickType_t timeout);

/// True while the channel is usable.
bool wble_l2cap_session_alive(void);

/// Disconnect the channel (if any) and drop all buffered state, so the next
/// wait_session() starts clean.
void wble_l2cap_end_session(void);

/// Read buffered bytes. Returns the count, 0 at end of stream, or
/// WBLE_ERR_WANT_READ when nothing has arrived yet.
ssize_t wble_l2cap_read(void *buf, size_t len);

/// Write up to one SDU. Returns the count consumed (which may be less than
/// len), or WBLE_ERR_WANT_WRITE when the peer has granted no credits.
ssize_t wble_l2cap_write(const void *buf, size_t len);

bool wble_l2cap_can_read(void);
bool wble_l2cap_can_write(void);

/// An eventfd that becomes readable whenever readiness may have changed. The
/// reader must drain it before sampling can_read()/can_write(), never after:
/// readiness is level state, and draining second loses a racing signal.
int wble_l2cap_wakeup_fd(void);

/// Block until can_read()/can_write() may have become true. Used by the
/// handshake, which owns its own task; the wcom loop uses the eventfd instead.
bool wble_l2cap_wait_readable(TickType_t timeout);
bool wble_l2cap_wait_writable(TickType_t timeout);

#endif
