#pragma once

#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Callbacks for WiFi protocol events ────────────────────────────── */

typedef struct {
    /** Called when a WASM binary has been downloaded over HTTP. */
    void (*on_upload_complete)(const uint8_t *data, uint32_t len, uint8_t slot);

    /** Called when a RUN command is received (unused for WiFi, reserved). */
    void (*on_run)(void);

    /** Called when a STOP command is received (unused for WiFi, reserved). */
    void (*on_stop)(void);

    /** Called when a RESET command is received (unused for WiFi, reserved). */
    void (*on_reset)(void);
} wendy_wifi_callbacks_t;

/* ── Public API ─────────────────────────────────────────────────────── */

/**
 * Initialize WiFi station, discover the Wendy server via mDNS,
 * download the WASM binary, and start a UDP listener for reload commands.
 *
 * This function blocks until WiFi is connected, then spawns background tasks
 * for discovery/download and UDP listening.
 */
esp_err_t wendy_wifi_init(const wendy_wifi_callbacks_t *callbacks);

/**
 * Deinitialize WiFi transport, stop listener tasks.
 */
void wendy_wifi_deinit(void);

#ifdef __cplusplus
}
#endif
