#pragma once
#include "wendy_net_direct_flows.h"
#include "wendy_pki.h"

/* Actor-owned adapter for app TLS. The app owner retains the TLS connection,
 * BIO channel, socket and cleanup worker throughout promotion. It must pump
 * encrypted channel I/O independently of the retained flow's plaintext pump.
 * In particular wendy_pki_fd is NOT the socket for buffered app TLS.
 *
 * retire is called exactly once when the flow relinquishes its reference. It
 * schedules owner cleanup; it must not free this adapter during the callback.
 * If drain_output is true, flush buffered ciphertext before destroying the
 * channel (subject to the owner's bounded drain deadline/transport failure).
 * TLS close_notify acceptance is not yet socket delivery for a buffered BIO.
 * Before externally disposing the owner, reset/close its retained flow so no
 * TLS callbacks can refer to freed memory. All access is root-actor serialized.
 * The owner must outlive this reference, including failed binding/commit. */
struct wn_direct_pki {
    wendy_pki_connection *connection;
    void *owner;
    void (*retire)(void *, bool drain_output);
    /* Optional readiness hooks. For buffered BIOs the app owner watches/pumps
     * the socket itself, and pending includes buffered encrypted input. */
    int (*fd)(void *);
    bool (*pending)(void *);
    bool retired, send_closed;
};
/* No allocation or TLS ownership transfer. Caller independently authenticates
 * app TLS and completes retained per-flow proof. Only successful commit gives
 * the flow a reference; on failure the caller retains all cleanup duties. */
struct wn_direct_upper wn_direct_pki_upper(struct wn_direct_pki *);
