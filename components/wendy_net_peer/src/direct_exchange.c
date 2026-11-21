#include "wendy_net_direct_exchange.h"
#include <mbedtls/platform_util.h>
#include <string.h>
static bool nonzero(const uint8_t *p, size_t n)
{
    uint8_t v = 0;
    while (n--)
        v |= *p++;
    return v != 0;
}
static bool initial_view(const struct wn_direct_recovery_view *v)
{
    return !v->count && !v->namespaces[0].high_water && !v->namespaces[1].high_water &&
           !v->namespaces[0].admitted && !v->namespaces[1].admitted;
}
static int initialize(struct wn_direct_exchange *e, const struct wn_direct_exchange_config *cfg,
                      const struct wn_direct_attachment *a)
{
    if (!e || !cfg || !cfg->gate || !cfg->token || !cfg->exporter || !cfg->apply ||
        cfg->binding.role > 1 || !nonzero(cfg->nonce, 16) ||
        !nonzero(cfg->binding.session_id, 32) || !nonzero(cfg->binding.capability, 32) ||
        !nonzero(cfg->binding.identity_digest, 32) || !wn_direct_recovery_view_valid(&cfg->local) ||
        cfg->remote_capacity > UINT16_MAX || (cfg->remote_capacity && !cfg->remote_records))
        return -1;
    if (wn_direct_generation_reserve(cfg->gate, cfg->token, a->generation,
                                     (enum wn_direct_mode)a->mode))
        return -1;
    memset(e, 0, sizeof *e);
    e->cfg = *cfg;
    e->attachment = *a;
    return 0;
}
static int prepare(struct wn_direct_exchange *e)
{
    const struct wn_direct_recovery_view *c = e->cfg.binding.role ? &e->remote : &e->cfg.local,
                                         *p = e->cfg.binding.role ? &e->cfg.local : &e->remote;
    if (wn_direct_recovery_digest(c, p, e->attachment.snapshot_digest))
        return -1;
    return wn_direct_transaction_prepare(&e->tx, &e->cfg.binding, e->cfg.gate, e->cfg.token,
                                         &e->attachment, e->cfg.nonce, &e->cfg.local, &e->remote,
                                         e->cfg.exporter, e->cfg.export_arg);
}
static int view_complete(struct wn_direct_exchange *e)
{
    if (!wn_direct_recovery_view_valid(&e->remote))
        return -1;
    if (!e->cfg.binding.role) {
        e->phase = WN_DX_WAIT_READY;
        return 0;
    }
    if (prepare(e))
        return -1;
    e->send_kind = WN_DIRECT_VIEW;
    e->send_index = 0;
    e->phase = WN_DX_WAIT_COMMIT;
    return 0;
}
static int start_view(struct wn_direct_exchange *e, const struct wn_direct_control *c)
{
    if (c->count > e->cfg.remote_capacity)
        return -1;
    struct wn_direct_recovery_view v = {0};
    memcpy(v.namespaces, c->namespaces, sizeof v.namespaces);
    if (!wn_direct_recovery_view_valid(&v))
        return -1;
    e->remote = v;
    e->remote.records = e->cfg.remote_records;
    e->remote_count = c->count;
    e->phase = WN_DX_WAIT_RECORDS;
    return c->count ? 0 : view_complete(e);
}
int wn_direct_exchange_coordinator(struct wn_direct_exchange *e,
                                   const struct wn_direct_exchange_config *cfg, uint32_t alias,
                                   uint64_t generation, enum wn_direct_mode mode, bool create)
{
    if (!cfg || cfg->binding.role || !alias || !generation ||
        (mode != WN_DIRECT_BLE && mode != WN_DIRECT_PROMOTED) ||
        (create && (mode != WN_DIRECT_BLE || !initial_view(&cfg->local))))
        return -1;
    struct wn_direct_attachment a = {
        .attachment_id = alias, .generation = generation, .mode = (uint8_t)mode};
    memcpy(a.session_id, cfg->binding.session_id, 32);
    memcpy(a.identity_digest, cfg->binding.identity_digest, 32);
    memcpy(a.coordinator_nonce, cfg->nonce, 16);
    if (initialize(e, cfg, &a))
        return -1;
    e->create = create;
    e->phase = WN_DX_WAIT_VIEW;
    e->send_kind = WN_DIRECT_OFFER;
    return 0;
}
int wn_direct_exchange_participant(struct wn_direct_exchange *e,
                                   const struct wn_direct_exchange_config *cfg,
                                   const struct wn_direct_control *offer)
{
    size_t ignored;
    if (!cfg || !offer || cfg->binding.role != 1 || offer->kind != WN_DIRECT_OFFER ||
        wn_direct_control_size(offer, &ignored) ||
        memcmp(offer->session_id, cfg->binding.session_id, 32))
        return -1;
    struct wn_direct_recovery_view v = {0};
    memcpy(v.namespaces, offer->namespaces, sizeof v.namespaces);
    if (offer->create && (offer->count || !initial_view(&v) || !initial_view(&cfg->local) ||
                          memcmp(offer->capability, cfg->binding.capability, 32)))
        return -1;
    struct wn_direct_attachment a = {.attachment_id = offer->attachment_id,
                                     .generation = offer->generation,
                                     .mode = (uint8_t)offer->mode};
    memcpy(a.session_id, cfg->binding.session_id, 32);
    memcpy(a.identity_digest, cfg->binding.identity_digest, 32);
    memcpy(a.coordinator_nonce, offer->nonce, 16);
    memcpy(a.participant_nonce, cfg->nonce, 16);
    if (initialize(e, cfg, &a))
        return -1;
    if (start_view(e, offer)) {
        wn_direct_exchange_lost(e);
        return -1;
    }
    return 0;
}
int wn_direct_exchange_next(const struct wn_direct_exchange *e, struct wn_direct_control *c)
{
    if (!e || !c)
        return -1;
    memset(c, 0, sizeof *c);
    if (e->phase == WN_DX_FAILED || !e->send_kind)
        return 0;
    c->kind = e->send_kind;
    c->attachment_id = e->attachment.attachment_id;
    switch (c->kind) {
    case WN_DIRECT_OFFER:
        c->generation = e->attachment.generation;
        c->mode = (enum wn_direct_mode)e->attachment.mode;
        c->create = e->create;
        memcpy(c->session_id, e->cfg.binding.session_id, 32);
        if (e->create)
            memcpy(c->capability, e->cfg.binding.capability, 32);
        /* fall through */
    case WN_DIRECT_VIEW:
        memcpy(c->nonce, e->cfg.nonce, 16);
        memcpy(c->namespaces, e->cfg.local.namespaces, sizeof c->namespaces);
        c->count = (uint16_t)e->cfg.local.count;
        break;
    case WN_DIRECT_RECORDS: {
        size_t left = e->cfg.local.count - e->send_index;
        c->record_count =
            (uint8_t)(left > WN_DIRECT_RECOVERY_BATCH ? WN_DIRECT_RECOVERY_BATCH : left);
        c->start = (uint16_t)e->send_index;
        memcpy(c->records, e->cfg.local.records + e->send_index,
               c->record_count * sizeof c->records[0]);
        break;
    }
    case WN_DIRECT_READY_PROOF:
    case WN_DIRECT_COMMIT_PROOF:
        memcpy(c->proof, e->tx.proof, 32);
        /* fall through */
    case WN_DIRECT_COMMIT_ACK:
        memcpy(c->context, e->tx.context, 32);
        break;
    default:
        return -1;
    }
    return 1;
}
int wn_direct_exchange_accepted(struct wn_direct_exchange *e)
{
    if (!e || e->phase == WN_DX_FAILED || !e->send_kind)
        return -1;
    uint8_t kind = e->send_kind;
    e->send_kind = 0;
    if (kind == WN_DIRECT_OFFER || kind == WN_DIRECT_VIEW || kind == WN_DIRECT_RECORDS) {
        if (kind == WN_DIRECT_RECORDS) {
            size_t left = e->cfg.local.count - e->send_index;
            e->send_index += left > WN_DIRECT_RECOVERY_BATCH ? WN_DIRECT_RECOVERY_BATCH : left;
        }
        if (e->send_index < e->cfg.local.count)
            e->send_kind = WN_DIRECT_RECORDS;
        else if (e->cfg.binding.role)
            e->send_kind = WN_DIRECT_READY_PROOF;
    }
    if (kind == WN_DIRECT_COMMIT_ACK) {
        if (wn_direct_transaction_activate(&e->tx)) {
            wn_direct_exchange_lost(e);
            return -1;
        }
        e->phase = WN_DX_ACTIVE;
    }
    return 0;
}
static int receive(struct wn_direct_exchange *e, const struct wn_direct_control *c)
{
    size_t ignored;
    if (!c || wn_direct_control_size(c, &ignored) ||
        c->attachment_id != e->attachment.attachment_id)
        return -1;
    switch (c->kind) {
    case WN_DIRECT_VIEW:
        if (e->cfg.binding.role || e->phase != WN_DX_WAIT_VIEW || e->send_kind)
            return -1;
        memcpy(e->attachment.participant_nonce, c->nonce, 16);
        return start_view(e, c);
    case WN_DIRECT_RECORDS:
        if (e->phase != WN_DX_WAIT_RECORDS || c->start != e->remote.count ||
            e->remote.count + c->record_count > e->remote_count ||
            (e->remote.count && c->records[0].id <= e->remote.records[e->remote.count - 1].id))
            return -1;
        memcpy(e->cfg.remote_records + e->remote.count, c->records,
               c->record_count * sizeof c->records[0]);
        e->remote.count += c->record_count;
        return e->remote.count == e->remote_count ? view_complete(e) : 0;
    case WN_DIRECT_READY_PROOF:
        if (e->cfg.binding.role || (e->phase != WN_DX_WAIT_READY && e->phase != WN_DX_WAIT_ACK &&
                                    e->phase != WN_DX_ACTIVE))
            return -1;
        if (!e->tx.gate && prepare(e))
            return -1;
        if (memcmp(c->context, e->tx.context, 32) ||
            wn_direct_transaction_peer_proof(&e->tx, c->proof, 32) ||
            wn_direct_transaction_commit(&e->tx, e->cfg.apply, e->cfg.apply_arg))
            return -1;
        if (!e->send_kind)
            e->send_kind = WN_DIRECT_COMMIT_PROOF;
        if (e->phase != WN_DX_ACTIVE)
            e->phase = WN_DX_WAIT_ACK;
        return 0;
    case WN_DIRECT_COMMIT_PROOF:
        if (e->cfg.binding.role != 1 ||
            (e->phase != WN_DX_WAIT_COMMIT && e->phase != WN_DX_ACTIVE) || !e->tx.gate ||
            (e->send_kind && e->send_kind != WN_DIRECT_COMMIT_ACK) ||
            memcmp(c->context, e->tx.context, 32))
            return -1;
        if (wn_direct_transaction_peer_proof(&e->tx, c->proof, 32) ||
            wn_direct_transaction_commit(&e->tx, e->cfg.apply, e->cfg.apply_arg))
            return -1;
        e->send_kind = WN_DIRECT_COMMIT_ACK;
        return 0;
    case WN_DIRECT_COMMIT_ACK:
        if (e->cfg.binding.role || (e->phase != WN_DX_WAIT_ACK && e->phase != WN_DX_ACTIVE) ||
            !e->tx.gate || e->send_kind || memcmp(c->context, e->tx.context, 32) ||
            wn_direct_transaction_activate(&e->tx))
            return -1;
        e->phase = WN_DX_ACTIVE;
        return 0;
    default:
        return -1;
    }
}
int wn_direct_exchange_receive(struct wn_direct_exchange *e, const struct wn_direct_control *c)
{
    if (!e || e->phase == WN_DX_FAILED)
        return -1;
    if (receive(e, c)) {
        wn_direct_exchange_lost(e);
        return -1;
    }
    return 0;
}
bool wn_direct_exchange_active(const struct wn_direct_exchange *e)
{
    return e && e->phase == WN_DX_ACTIVE;
}
void wn_direct_exchange_lost(struct wn_direct_exchange *e)
{
    if (!e)
        return;
    wn_direct_generation_lost(e->cfg.gate, e->cfg.token);
    e->phase = WN_DX_FAILED;
    e->send_kind = 0;
    wn_direct_transaction_clear(&e->tx);
    mbedtls_platform_zeroize(e->cfg.binding.capability, 32);
}
