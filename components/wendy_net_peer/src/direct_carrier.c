#include "wendy_net_direct_carrier.h"
#include "wendy_net_alloc.h"
#include <mbedtls/platform_util.h>
#include <string.h>

enum { REUSE_PROPOSE = 22, REUSE_ACCEPT, REUSE_BUSY, REUSE_UNAVAILABLE };

static void discard_offer(uint8_t *offer)
{
    if (offer) {
        mbedtls_platform_zeroize(offer, 137);
        wendy_net_free(offer);
    }
}

static int receive(void *arg, const void *bytes, size_t size)
{
    struct wn_direct_carrier *b = arg;
    if (!bytes || size < 5 || size > WN_DIRECT_MAX_FRAME)
        return WNC_INVALID;
    const uint8_t *wire = bytes;
    uint32_t alias =
        (uint32_t)wire[1] << 24 | (uint32_t)wire[2] << 16 | (uint32_t)wire[3] << 8 | wire[4];
    if (!alias)
        return WNC_INVALID;
    if (alias < b->alias || (!b->session && alias == b->alias))
        return 0;
    if (!b->session) {
        if (b->alias != UINT32_MAX && alias == b->alias + 1 && size == 5 &&
            wire[0] >= REUSE_PROPOSE && wire[0] <= REUSE_UNAVAILABLE) {
            if (b->proposal_received)
                return WNC_INVALID;
            b->proposal_received = wire[0];
            return 0;
        }
        struct wn_direct_control offer;
        if (!b->proposal_accepted || b->alias == UINT32_MAX || alias != b->alias + 1 ||
            b->parked_offer || size != 137 || wn_direct_control_decode(bytes, size, &offer) ||
            offer.kind != WN_DIRECT_OFFER || !offer.create || offer.mode != WN_DIRECT_BLE ||
            offer.count)
            return WNC_INVALID;
        b->parked_offer = wendy_net_malloc(size);
        if (!b->parked_offer)
            return WNC_NOMEM;
        memcpy(b->parked_offer, bytes, size);
        return 0;
    }
    uint32_t id = 0;
    int result =
        wn_direct_session_receive(b->session, b->token, bytes, size, b->now(b->clock_arg), &id);
    if (result)
        return result;
    if (id) {
        struct wn_direct_flow *f = wn_direct_flows_find(b->session->cfg.flows, id);
        if (!f)
            return WNC_INVALID;
        uint16_t refusal = b->open(b->open_arg, id, f->request);
        if (refusal && wn_direct_session_complete(b->session, id, refusal, -1))
            return WNC_INVALID;
    }
    return 0;
}
int wn_direct_carrier_defer(struct wn_direct_carrier *b, struct wnc_carrier *c, uint8_t role,
                            int64_t (*now)(void *), void *clock_arg,
                            uint16_t (*open)(void *, uint32_t, struct wn_direct_request),
                            void *open_arg)
{
    if (!b || b->carrier || b->session || !c || role > 1 || !now || !open || c->direct_receive)
        return WNC_INVALID;
    if (wnc_enable_direct(c, receive, b))
        return WNC_INVALID;
    *b = (struct wn_direct_carrier){.carrier = c,
                                    .role = role,
                                    .now = now,
                                    .clock_arg = clock_arg,
                                    .open = open,
                                    .open_arg = open_arg};
    return 0;
}
int wn_direct_carrier_bind(struct wn_direct_carrier *b, struct wn_direct_session *s,
                           struct wnc_carrier *c, int64_t (*now)(void *), void *clock_arg,
                           uint16_t (*open)(void *, uint32_t, struct wn_direct_request),
                           void *open_arg)
{
    if (!b || b->session || !s || s->closed || !s->attached || s->carrier_owner || !c || !now ||
        !open)
        return WNC_INVALID;
    // A failed bind must not overwrite an adapter still referenced by a carrier.
    bool parked = b->carrier != NULL;
    if (parked) {
        if (b->carrier != c || c->direct_receive != receive || c->direct_context != b ||
            !b->proposal_accepted || !b->proposal_held || b->alias == UINT32_MAX ||
            s->alias != b->alias + 1)
            return WNC_INVALID;
    } else if (c->direct_receive)
        return WNC_INVALID;
    struct wn_direct_carrier next = {.session = s,
                                     .carrier = c,
                                     .token = s->token,
                                     .alias = s->alias,
                                     .role = s->cfg.role,
                                     .now = now,
                                     .clock_arg = clock_arg,
                                     .open = open,
                                     .open_arg = open_arg};
    if (!parked && wnc_enable_direct(c, receive, b))
        return WNC_INVALID;
    uint8_t *offer = b->parked_offer;
    *b = next;
    s->carrier_owner = b;
    int result = offer ? receive(b, offer, 137) : 0;
    discard_offer(offer);
    return result;
}
int wn_direct_carrier_flush(struct wn_direct_carrier *b, unsigned max_records)
{
    if (!b || !b->session || !b->carrier || !max_records || b->carrier->direct_context != b ||
        b->carrier->direct_receive != receive)
        return WNC_INVALID;
    struct wn_direct_session *s = b->session;
    if (s->closed || !s->attached || s->token != b->token || s->carrier_owner != b)
        return WNC_INVALID;
    int progress = 0;
    for (unsigned i = 0; i < max_records; i++) {
        const uint8_t *wire;
        size_t size;
        int ready = wn_direct_session_next(s, b->now(b->clock_arg), &wire, &size);
        if (ready < 0)
            return WNC_INVALID;
        if (!ready)
            return progress;
        int queued = wnc_enqueue_direct(b->carrier, wire, size);
        if (queued == WNC_LIMIT || queued == WNC_NOMEM)
            return progress;
        if (queued)
            return queued;
        // Enqueue owns a COPY now. Advance before pump can deliver a peer response.
        if (wn_direct_session_accepted(s))
            return WNC_INVALID;
        progress = 1;
    }
    return progress;
}
int wn_direct_carrier_unbind(struct wn_direct_carrier *b, int64_t now)
{
    if (!b || !b->carrier || b->carrier->io.write)
        return WNC_INVALID;
    if (b->session)
        wn_direct_session_lost(b->session, b->token, now);
    discard_offer(b->parked_offer);
    memset(b, 0, sizeof *b);
    return 0;
}

int wn_direct_carrier_retire(struct wn_direct_carrier *b, int64_t now)
{
    if (!b || !b->carrier || b->carrier->direct_context != b ||
        b->carrier->direct_receive != receive)
        return WNC_INVALID;
    if (b->session && (b->session->carrier_owner != b || b->session->token != b->token))
        return WNC_INVALID;
    if (wnc_retire_direct(b->carrier))
        return WNC_INVALID;
    if (b->session)
        wn_direct_session_lost(b->session, b->token, now);
    discard_offer(b->parked_offer);
    memset(b, 0, sizeof *b);
    return 0;
}

int wn_direct_carrier_park(struct wn_direct_carrier *b, int64_t now)
{
    if (!b || !b->session || !b->carrier || b->session->carrier_owner != b ||
        b->session->token != b->token || b->carrier->direct_context != b ||
        b->carrier->direct_receive != receive || !b->alias || b->alias == UINT32_MAX ||
        b->parked_offer)
        return WNC_INVALID;
    wn_direct_session_lost(b->session, b->token, now);
    b->session = NULL;
    b->token = 0;
    return 0;
}

int wn_direct_carrier_propose(struct wn_direct_carrier *b, bool retired, bool permitted,
                              bool (*reserve)(void *), void (*release)(void *), void *arg,
                              int64_t now)
{
    if (!b || b->session || !b->carrier || b->alias == UINT32_MAX || b->role > 1 || !reserve ||
        !release || b->carrier->direct_context != b || b->carrier->direct_receive != receive)
        return WNC_INVALID;
    uint8_t received = b->proposal_received;
    b->proposal_received = 0;
    /* A suspended peer cannot hold fresh application admission forever while
     * unrelated routed traffic keeps the physical carrier alive. */
    if (b->proposal_held && now >= b->proposal_deadline) {
        release(arg);
        b->proposal_held = false;
        return WNC_TIMEOUT;
    }
    if (received == REUSE_UNAVAILABLE) {
        if (b->proposal_held) {
            release(arg);
            b->proposal_held = false;
        }
        return 2;
    }
    if (received == REUSE_PROPOSE) {
        if (b->role != 1 || b->proposal_held || b->proposal_outgoing || b->proposal_accepted)
            return WNC_INVALID;
        b->proposal_outgoing = REUSE_BUSY;
        if (retired && permitted && reserve(arg)) {
            b->proposal_held = true;
            b->proposal_outgoing = REUSE_ACCEPT;
            b->proposal_deadline =
                now > INT64_MAX - INT64_C(60000000) ? INT64_MAX : now + INT64_C(60000000);
        }
    } else if (received == REUSE_ACCEPT) {
        if (b->role != 0 || !b->proposal_sent || !b->proposal_held)
            return WNC_INVALID;
        b->proposal_accepted = true;
    } else if (received == REUSE_BUSY) {
        if (b->role != 0 || !b->proposal_sent || !b->proposal_held)
            return WNC_INVALID;
        release(arg);
        b->proposal_held = false;
        b->proposal_sent = false;
        if (!b->proposal_retry_delay)
            b->proposal_retry_delay = 250000;
        b->proposal_retry = now + b->proposal_retry_delay;
        if (b->proposal_retry_delay < 4000000)
            b->proposal_retry_delay *= 2;
    }
    if (retired && !permitted) {
        if (b->proposal_held) {
            release(arg);
            b->proposal_held = false;
        }
        b->proposal_outgoing = REUSE_UNAVAILABLE;
    }
    if (b->role == 0 && retired && permitted && !b->proposal_held && !b->proposal_outgoing &&
        now >= b->proposal_retry && reserve(arg)) {
        b->proposal_held = true;
        b->proposal_outgoing = REUSE_PROPOSE;
        b->proposal_deadline =
            now > INT64_MAX - INT64_C(60000000) ? INT64_MAX : now + INT64_C(60000000);
    }
    if (b->proposal_outgoing) {
        uint32_t alias = b->alias + 1;
        uint8_t wire[5] = {b->proposal_outgoing, (uint8_t)(alias >> 24), (uint8_t)(alias >> 16),
                           (uint8_t)(alias >> 8), (uint8_t)alias};
        int result = wnc_enqueue_direct(b->carrier, wire, sizeof wire);
        if (result == WNC_LIMIT || result == WNC_NOMEM)
            return 0;
        if (result)
            return result;
        if (b->proposal_outgoing == REUSE_PROPOSE)
            b->proposal_sent = true;
        if (b->proposal_outgoing == REUSE_ACCEPT)
            b->proposal_accepted = true;
        if (b->proposal_outgoing == REUSE_UNAVAILABLE) {
            b->proposal_outgoing = 0;
            return 2;
        }
        b->proposal_outgoing = 0;
    }
    return b->proposal_accepted ? 1 : 0;
}
