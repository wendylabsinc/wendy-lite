/* SPDX-License-Identifier: Apache-2.0 */
#pragma once
#include "esp_err.h"
#include "wendy_pki.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define WBLE_MESH_TIME_PSM 130

struct wble_mesh_pipe;
struct wble_mesh_peer
{
    uint8_t address[6], address_type;
    uint16_t psm;
    bool server;
};
typedef void (*wble_mesh_report)(void *, const uint8_t address[6],
                                 uint8_t address_type,
                                 const void *advertisement, size_t, int rssi);
/* Requires the existing NimBLE host to be synchronized. Initialization is an
 * asynchronous host effect: INVALID_STATE also means pending; poll again from
 * the outer driver. Separate PSM/channel ownership from WendyCom. */
esp_err_t wble_mesh_init(void);
/* Stop mesh-only scanning and drain CoCs before releasing dynamic resources.
 * Management advertising, its CoCs and the NimBLE host remain untouched. */
bool wble_mesh_stop(void);
/* Actor-owned resource hint. Reject new router CoCs before allocating a pipe
 * when no setup slot is available; signed-time and WendyCom remain separate.
 * Discovery and established channels are unaffected. Defaults to accepting. */
void wble_mesh_router_admission(bool available);
/* Actor-only, nonblocking snapshot: registered mesh listeners and an actually
 * free private pipe (including pending/closing ownership). No reservation. */
bool wble_mesh_incoming_available(void);
/* Actor capacity hint for owned discovery only. Retains reports/candidates,
 * never cancels a queued dial, and leaves baseline/shared scanning untouched.
 * Changes coalesce on the existing host mailbox, without an HCI wait here. */
void wble_mesh_scan_interest(bool available);
esp_err_t wble_mesh_scan(wble_mesh_report, void *context);
esp_err_t wble_mesh_dial(const uint8_t address[6], uint8_t address_type,
                         uint16_t psm);
/* Scan/dial APIs only submit bounded host effects. Collect a command error
 * without waiting; procedure completion and pipes arrive through normal I/O. */
int wble_mesh_poll_error(unsigned *operation);
/* Future error-retry deadline only; INT64_MAX when none is scheduled. */
int64_t wble_mesh_retry_deadline(void);
/* One owner per returned pipe. The caller closes TLS before release. */
struct wble_mesh_pipe *wble_mesh_take(struct wble_mesh_peer *);
struct wendy_pki_stream wble_mesh_stream(struct wble_mesh_pipe *);
void wble_mesh_release(struct wble_mesh_pipe *);
size_t wble_mesh_memory(void);
#if CONFIG_WENDY_NET_TEST_BLE_STREAM_CRC
/* Existing diagnostics caller; takes a zero-wait snapshot and logs outside
 * the metadata gate. No raw payloads. OFF lifetime is protected. */
void wble_mesh_crc_diagnose(void);
#endif
/* Multiplex the existing legacy management advertisement with a native
 *31byte mesh advertisement, retaining both primary service advertisements. */
esp_err_t wendy_ble_mesh_advertisement(const uint8_t *data, size_t size);
bool wendy_ble_mesh_advertisement_idle(void);

/* Readiness-only notification. Never transfers pipe ownership. */
void wble_mesh_set_wakeup(void (*wake)(void));

/* Conservative host-only GAP ownership probe: includes accepted/pending and
 * closing channel state. Unknown lifetime/contention returns true. */
bool wble_mesh_uses_connection(uint16_t handle);
