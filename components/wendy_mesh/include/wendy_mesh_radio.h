#pragma once
#include "wendy_pki.h"
/* One carrier owns a session. Closing TLS does not close the carrier. */
struct wm_carrier {
    struct wendy_pki_stream stream;
    void (*close)(void);
    bool server;
    const char* name;
};
int wm_ble_open(struct wm_carrier* carrier);
int wm_espnow_open(struct wm_carrier* carrier);
