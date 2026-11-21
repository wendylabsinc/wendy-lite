#include "wendy_net_direct_session.h"
#include "recovery_lifetime.h"
#include <mbedtls/platform_util.h>
#include <string.h>
static bool nonzero(const uint8_t *p, size_t n)
{
    uint8_t v = 0;
    while (n--)
        v |= *p++;
    return v != 0;
}
static int64_t after(int64_t now, int64_t delta)
{
    return now > INT64_MAX - delta ? INT64_MAX : now + delta;
}
static int fail(struct wn_direct_session *s)
{
    wn_direct_session_close(s);
    return WN_DIRECT_BOUNDS;
}
static int check(struct wn_direct_session *s, int64_t now)
{
    if (!s || !s->initialized || s->closed)
        return WN_DIRECT_BOUNDS;
    if (now < s->now || now < 0)
        return fail(s);
    s->now = now;
    if (s->cfg.check) {
        int64_t deadline = s->security_deadline;
        if (s->cfg.check(s->cfg.check_arg, now, &deadline))
            return fail(s);
        if (deadline < s->security_deadline)
            s->security_deadline = deadline;
    }
    if (now >= s->security_deadline || (s->outage_deadline && now >= s->outage_deadline) ||
        (s->promotion_deadline && now >= s->promotion_deadline))
        return fail(s);
    return 0;
}
int wn_direct_session_init(struct wn_direct_session *s, const struct wn_direct_session_config *cfg,
                           int64_t now)
{
    if (!s || !cfg || !cfg->flows || cfg->flows->closed || cfg->flows->alias || cfg->flows->count ||
        cfg->flows->opens[0].admitted || cfg->flows->opens[1].admitted ||
        cfg->flows->role != cfg->role || cfg->role > 1 || !nonzero(cfg->identity_digest, 32) ||
        now < 0 || cfg->deadline <= now || cfg->recovery_us < 0 || !cfg->random || !cfg->local ||
        !cfg->remote || !cfg->scratch || !cfg->plan || !wn_direct_selected_transport(cfg->selected))
        return WN_DIRECT_BOUNDS;
    *s = (struct wn_direct_session){
        .cfg = *cfg, .initialized = true, .now = now, .security_deadline = cfg->deadline};
    if (!s->cfg.recovery_us)
        s->cfg.recovery_us = WN_RECOVERY_GRACE_US;
    s->binding.role = cfg->role;
    memcpy(s->binding.identity_digest, cfg->identity_digest, 32);
    if (wn_direct_generation_init_pending(&s->gate))
        return fail(s);
    if (!cfg->role && (cfg->random(cfg->random_arg, s->binding.session_id, 32) ||
                       cfg->random(cfg->random_arg, s->binding.capability, 32) ||
                       !nonzero(s->binding.session_id, 32) || !nonzero(s->binding.capability, 32)))
        return fail(s);
    return 0;
}
void wn_direct_session_close(struct wn_direct_session *s)
{
    if (!s || !s->initialized || s->closed)
        return;
    s->closed = true;
    s->attached = s->active = false;
    s->wire_size = 0;
    wn_direct_generation_close(&s->gate);
    wn_direct_flows_close(s->cfg.flows);
    mbedtls_platform_zeroize(&s->exchange, sizeof s->exchange);
    mbedtls_platform_zeroize(s->binding.capability, sizeof s->binding.capability);
    mbedtls_platform_zeroize(s->wire, sizeof s->wire);
    s->exporter = NULL;
    s->export_arg = NULL;
    s->carrier_owner = NULL;
}
int wn_direct_session_retire(struct wn_direct_session *s)
{
    if (!s || s->closed || !s->active || s->mode != WN_DIRECT_PROMOTED || s->wire_size ||
        !wn_direct_flows_retirement_ready(s->cfg.flows))
        return 0;
    s->retired = true;
    wn_direct_session_close(s);
    return 1;
}
static int apply(void *arg)
{
    struct wn_direct_session *s = arg;
    return wn_direct_flows_recover(s->cfg.flows, &s->exchange.remote, s->now, s->cfg.scratch,
                                   (size_t)2 * s->cfg.flows->slots, s->cfg.plan,
                                   (size_t)4 * s->cfg.flows->slots);
}
static int prepare(struct wn_direct_session *s, const struct wn_direct_control *offer)
{
    struct wn_direct_exchange_config cfg = {.binding = s->binding,
                                            .gate = &s->gate,
                                            .token = s->token,
                                            .remote_records = s->cfg.remote,
                                            .remote_capacity = (size_t)2 * s->cfg.flows->slots,
                                            .exporter = s->exporter,
                                            .export_arg = s->export_arg,
                                            .apply = apply,
                                            .apply_arg = s};
    memcpy(cfg.nonce, s->nonce, 16);
    if (wn_direct_flows_snapshot(s->cfg.flows, s->cfg.local, (size_t)2 * s->cfg.flows->slots,
                                 &cfg.local))
        return fail(s);
    int result;
    if (offer) {
        s->alias = offer->attachment_id;
        result = wn_direct_exchange_participant(&s->exchange, &cfg, offer);
    } else {
        uint64_t generation;
        if (!wn_direct_generation_next(&s->gate, &generation))
            return fail(s);
        result = wn_direct_exchange_coordinator(&s->exchange, &cfg, s->alias, generation, s->mode,
                                                !s->peer_known);
    }
    if (result)
        return fail(s);
    s->exchanging = true;
    return 0;
}
static int activate(struct wn_direct_session *s)
{
    if (!s->active && s->exchanging && wn_direct_exchange_active(&s->exchange)) {
        if (s->mode == WN_DIRECT_PROMOTED ? wn_direct_flows_bind_promoted(s->cfg.flows, s->alias)
                                          : wn_direct_flows_bind(s->cfg.flows, s->alias))
            return fail(s);
        s->active = true;
        s->outage_deadline = 0;
        s->promotion_deadline = 0;
    }
    return 0;
}
static void suspend(struct wn_direct_session *s, int64_t now)
{
    if (s->exchanging)
        wn_direct_exchange_lost(&s->exchange);
    else
        (void)wn_direct_generation_lost(&s->gate, s->token);
    wn_direct_flows_suspend(s->cfg.flows);
    s->attached = s->active = s->exchanging = false;
    s->wire_size = 0;
    s->exporter = NULL;
    s->export_arg = NULL;
    s->carrier_owner = NULL;
    mbedtls_platform_zeroize(&s->exchange, sizeof s->exchange);
    mbedtls_platform_zeroize(s->wire, sizeof s->wire);
    if (!s->outage_deadline)
        s->outage_deadline = after(now, s->cfg.recovery_us);
}
static int attach_mode(struct wn_direct_session *s, uint64_t token, uint32_t alias,
                       const uint8_t identity[32], uint32_t selected, int64_t deadline,
                       wn_direct_exporter exporter, void *arg, int64_t now,
                       enum wn_direct_mode mode, bool initiator)
{
    if (check(s, now))
        return WN_DIRECT_BOUNDS;
    if (!identity || memcmp(identity, s->binding.identity_digest, 32) ||
        selected != s->cfg.selected)
        return fail(s);
    if (!token || token <= s->last_token || !alias || !exporter || deadline <= now)
        return WN_DIRECT_BOUNDS;
    if (s->attached) {
        if (mode != WN_DIRECT_PROMOTED || s->mode != WN_DIRECT_PROMOTED)
            return WN_DIRECT_CAPACITY;
        /* Local dial provenance, never a peer claim. The coordinator's physical
         * dial wins only while replacing it cannot undo a possible COMMIT. */
        bool preferred = initiator == (s->binding.role == 0);
        bool incumbent = s->promotion_initiator == (s->binding.role == 0);
        if (!preferred || incumbent || s->active || s->gate.phase >= WN_DIRECT_COMMITTING)
            return WN_DIRECT_RETIRED;
        suspend(s, now);
    }
    if ((s->mode == WN_DIRECT_PROMOTED && mode != WN_DIRECT_PROMOTED) ||
        s->cfg.flows->upper_control)
        return WN_DIRECT_RETIRED;
    if (mode == WN_DIRECT_PROMOTED &&
        (!nonzero(s->binding.session_id, 32) || (!s->binding.role && !s->peer_known)))
        return WN_DIRECT_CAPACITY;
    if (deadline < s->security_deadline)
        s->security_deadline = deadline;
    s->mode = mode;
    s->promotion_initiator = initiator;
    s->last_token = s->token = token;
    s->alias = alias;
    s->exporter = exporter;
    s->export_arg = arg;
    s->attached = true;
    s->active = s->exchanging = false;
    s->wire_size = 0;
    s->setup_deadline = after(now, INT64_C(60000000));
    if (mode == WN_DIRECT_PROMOTED) {
        if (!s->promotion_deadline)
            s->promotion_deadline = s->setup_deadline;
        s->setup_deadline = s->promotion_deadline; /* Never renew setup on reconnect. */
    }
    if (s->cfg.random(s->cfg.random_arg, s->nonce, 16) || !nonzero(s->nonce, 16))
        return fail(s);
    if (!s->binding.role)
        return prepare(s, NULL);
    return 0;
}
int wn_direct_session_attach(struct wn_direct_session *s, uint64_t token, uint32_t alias,
                             const uint8_t identity[32], uint32_t selected, int64_t deadline,
                             wn_direct_exporter exporter, void *arg, int64_t now)
{
    return attach_mode(s, token, alias, identity, selected, deadline, exporter, arg, now,
                       WN_DIRECT_BLE, false);
}
int wn_direct_session_promote(struct wn_direct_session *s, uint64_t token, uint32_t alias,
                              const uint8_t identity[32], uint32_t selected, int64_t deadline,
                              wn_direct_exporter exporter, void *arg, bool initiator, int64_t now)
{
    return attach_mode(s, token, alias, identity, selected, deadline, exporter, arg, now,
                       WN_DIRECT_PROMOTED, initiator);
}
void wn_direct_session_lost(struct wn_direct_session *s, uint64_t token, int64_t now)
{
    if (!s || !s->initialized || s->closed || !s->attached || token != s->token)
        return;
    if (check(s, now))
        return;
    /* Before COMMIT, the peer cannot have exposed raw traffic. Retain the
     * epoch while fencing this candidate; promotion remains one-way. */
    if (s->mode == WN_DIRECT_PROMOTED && (s->active || s->gate.phase >= WN_DIRECT_COMMITTING)) {

        wn_direct_session_close(s);
        return;
    }
    suspend(s, now);
}
int wn_direct_session_tick(struct wn_direct_session *s, int64_t now)
{
    if (check(s, now))
        return WN_DIRECT_BOUNDS;
    if (wn_direct_session_frozen(s))
        return now >= s->setup_deadline
                   ? (s->mode == WN_DIRECT_PROMOTED ? fail(s) : WN_DIRECT_CARRIER_LOST)
                   : 0;
    return wn_direct_flows_poll(s->cfg.flows);
}
int wn_direct_session_next(struct wn_direct_session *s, int64_t now, const uint8_t **wire,
                           size_t *size)
{
    if (!wire || !size)
        return WN_DIRECT_BOUNDS;
    *wire = NULL;
    *size = 0;
    if (check(s, now))
        return WN_DIRECT_BOUNDS;
    if (!s->attached)
        return 0;
    if (s->wire_size) {
        *wire = s->wire;
        *size = s->wire_size;
        return 1;
    }
    struct wn_direct_control control;
    int ready = s->exchanging ? wn_direct_exchange_next(&s->exchange, &control) : 0;
    if (ready < 0)
        return fail(s);
    s->output_control = ready != 0;
    if (ready) {
        if (wn_direct_control_encode(&control, s->wire, sizeof s->wire, &s->wire_size))
            return fail(s);
    } else if (s->active) {
        struct wn_direct_frame frame;
        ready = wn_direct_flows_prepare(s->cfg.flows, now, &frame);
        if (ready < 0)
            return fail(s);
        if (ready && wn_direct_frame_encode(&frame, s->wire, sizeof s->wire, &s->wire_size))
            return fail(s);
    }
    if (!ready)
        return 0;
    *wire = s->wire;
    *size = s->wire_size;
    return 1;
}
int wn_direct_session_accepted(struct wn_direct_session *s)
{
    if (!s || s->closed || !s->attached || !s->wire_size)
        return WN_DIRECT_BOUNDS;
    int result = s->output_control ? wn_direct_exchange_accepted(&s->exchange)
                                   : wn_direct_flows_accepted(s->cfg.flows);
    s->wire_size = 0;
    if (result)
        return fail(s);
    return activate(s);
}
int wn_direct_session_receive(struct wn_direct_session *s, uint64_t token, const uint8_t *wire,
                              size_t size, int64_t now, uint32_t *fresh)
{
    if (!fresh)
        return WN_DIRECT_BOUNDS;
    *fresh = 0;
    if (!s || !s->initialized || s->closed)
        return WN_DIRECT_BOUNDS;
    // A fenced old worker may carry an old timestamp as well as an old token.
    // Ignore it before clock/policy processing; it cannot kill the new attachment.
    if (!s->attached || token != s->token)
        return WN_DIRECT_RETIRED;
    if (check(s, now))
        return WN_DIRECT_BOUNDS;
    if (!wire || !size || size > WN_DIRECT_MAX_FRAME)
        return fail(s);
    if (wire[0] >= WN_DIRECT_OFFER) {
        struct wn_direct_control control;
        if (wn_direct_control_decode(wire, size, &control))
            return fail(s);
        if (!s->exchanging) {
            if (s->binding.role != 1 || control.kind != WN_DIRECT_OFFER || control.mode != s->mode)
                return fail(s);
            if (!nonzero(s->binding.session_id, 32)) {
                if (!control.create)
                    return fail(s);
                memcpy(s->binding.session_id, control.session_id, 32);
                memcpy(s->binding.capability, control.capability, 32);
            }
            if (prepare(s, &control))
                return WN_DIRECT_BOUNDS;
        } else {
            if (wn_direct_exchange_receive(&s->exchange, &control))
                return fail(s);
            if (!s->binding.role && control.kind == WN_DIRECT_READY_PROOF)
                s->peer_known = true;
        }
        return activate(s);
    }
    if (!s->active ||
        !wn_direct_generation_allows(&s->gate, token, s->exchange.attachment.generation))
        return fail(s);
    struct wn_direct_frame frame;
    if (wn_direct_frame_decode(wire, size, &frame) ||
        wn_direct_flows_receive(s->cfg.flows, &frame, now, fresh))
        return fail(s);
    return 0;
}
int wn_direct_session_complete(struct wn_direct_session *s, uint32_t id, uint16_t result, int fd)
{
    if (!s || !s->initialized || s->closed || (result && fd >= 0) || (!result && fd < 0))
        return WN_DIRECT_BOUNDS;
    if (wn_direct_session_frozen(s))
        return WN_DIRECT_CAPACITY;
    if (wn_direct_flows_complete(s->cfg.flows, id, result))
        return WN_DIRECT_RETIRED;
    if (!result && wn_direct_flows_socket(s->cfg.flows, id, fd)) {
        (void)wn_direct_flows_reset(s->cfg.flows, id, WN_DIRECT_IO);
        return WN_DIRECT_BOUNDS;
    }
    return 0;
}
int wn_direct_session_complete_memory(struct wn_direct_session *s, uint32_t id)
{
    if (!s || !s->initialized || s->closed)
        return WN_DIRECT_BOUNDS;
    if (wn_direct_session_frozen(s))
        return WN_DIRECT_CAPACITY;
    return wn_direct_flows_complete(s->cfg.flows, id, 0);
}

int wn_direct_session_start_binding(struct wn_direct_session *s, uint32_t id,
                                    struct wn_direct_promoted_binding *binding, int initiator,
                                    int (*exporter)(void *, const char *, const uint8_t[32],
                                                    uint8_t[32]),
                                    void *arg, int64_t now)
{
    if (check(s, now) || !binding || !exporter || !s->active || s->mode != WN_DIRECT_PROMOTED ||
        !wn_direct_exchange_active(&s->exchange))
        return WN_DIRECT_BOUNDS;
    struct wn_direct_flow *f = wn_direct_flows_find(s->cfg.flows, id);
    struct wn_direct_open_entry e;
    if (!f || f->reset || f->promoted || f->binding || (!f->has_lane && !f->packet) ||
        wn_direct_flows_open(s->cfg.flows, id, &e) || e.local_closed ||
        e.remote_closed)
        return WN_DIRECT_RETIRED;
    if (!e.complete)
        return WN_DIRECT_CAPACITY;
    if (e.result)
        return WN_DIRECT_RETIRED;
    uint8_t nonce[16], digest[32];
    if (s->cfg.random(s->cfg.random_arg, nonce, 16) ||
        wn_direct_request_digest(f->request, digest) ||
        wn_direct_promoted_init(binding, &s->exchange.attachment, id, digest, s->binding.capability,
                                s->binding.role, nonce, initiator, exporter, arg))
        return WN_DIRECT_BOUNDS;
    f->binding = binding;
    return 0;
}
int wn_direct_session_commit_flow(struct wn_direct_session *s, uint32_t id,
                                  struct wn_direct_promoted_binding *binding,
                                  const struct wn_direct_upper *upper, int64_t now)
{
    if (check(s, now) || !s->active || s->mode != WN_DIRECT_PROMOTED || !binding ||
        !binding->done || binding->failed)
        return WN_DIRECT_BOUNDS;
    struct wn_direct_flow *f = wn_direct_flows_find(s->cfg.flows, id);
    uint8_t expected[32], digest[32];
    if (!f || f->binding != binding || binding->flow_id != id || binding->role != s->binding.role ||
        wn_direct_attachment_context(&s->exchange.attachment, expected) ||
        memcmp(expected, binding->attachment_context, 32) ||
        wn_direct_request_digest(f->request, digest) || memcmp(digest, binding->open_digest, 32))
        return WN_DIRECT_BOUNDS;
    int r = wn_direct_flows_promote(s->cfg.flows, id, upper);
    if (!r)
        f->binding = NULL;
    return r;
}
