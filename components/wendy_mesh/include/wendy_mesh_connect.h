#pragma once
#include "wendy_mesh_radio.h"
#include "wendy_pki_mesh.h"
#include "wendy_mesh_status.h"

struct wm_mesh_connection {
    wendy_pki_connection* connection;
    struct wendy_pki_mesh_identity identity;
    struct wm_carrier carrier;
};

/* Start with zeroed storage. The caller closes any TLS connection, then the
 * carrier, on success or failure. Only one transport is authenticated at once. */
int wm_mesh_connect(struct wm_mesh_connection* attempt,
    void (*phase)(enum wendy_mesh_phase));
