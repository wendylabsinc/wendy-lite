#include "wendy_net_direct_lane.h"
#include <string.h>
static struct wn_direct_receipt receipt(const struct wn_direct_receiver *r)
{
    return (struct wn_direct_receipt){r->buffer.end, r->buffer.limit, r->finished};
}
static bool valid(const struct wn_direct_lane *l)
{
    return l && l->id && l->sender && l->receiver;
}
static bool time_valid(const struct wn_direct_lane *l, int64_t now)
{
    return now >= 0 && (!l->ack.pending || now >= l->ack.since);
}
int wn_direct_lane_init(struct wn_direct_lane *l, uint32_t id, struct wn_direct_sender *s,
                        struct wn_direct_receiver *r, int64_t now)
{
    if (!l || !id || !s || !r || !s->buffer.pool || !r->buffer.pool || now < 0)
        return -1;
    memset(l, 0, sizeof *l);
    l->id = id;
    l->sender = s;
    l->receiver = r;
    l->cursor = s->buffer.start;
    return wn_direct_ack_init(&l->ack, receipt(r), now);
}
int wn_direct_lane_prepare(struct wn_direct_lane *l, uint32_t alias, int64_t now, uint8_t *scratch,
                           size_t cap, struct wn_direct_frame *f)
{
    if (!valid(l) || !alias || !scratch || cap < WN_DIRECT_MAX_DATA || !f || l->pending_kind)
        return -1;
    memset(f, 0, sizeof *f);
    if (wn_direct_ack_update(&l->ack, receipt(l->receiver), now))
        return -1;
    struct wn_direct_receipt state;
    f->attachment_id = alias;
    if (wn_direct_ack_due(&l->ack, now, &state)) {
        f->kind = WN_DIRECT_STATE;
        f->state_count = 1;
        f->states[0] =
            (struct wn_direct_state_entry){l->id, state.received, state.limit, state.fin_seen};
        l->pending_state = state;
    } else if (l->sender->finished && !l->fin_sent && !l->fin_ack) {
        f->kind = WN_DIRECT_FIN;
        f->flow_id = l->id;
        f->value = l->sender->final;
    } else {
        size_t n;
        if (wn_direct_send_offer(l->sender, l->cursor, scratch, WN_DIRECT_MAX_DATA, &n))
            return -1;
        if (!n) {
            memset(f, 0, sizeof *f);
            return 0;
        }
        f->kind = WN_DIRECT_DATA;
        f->flow_id = l->id;
        f->payload = scratch;
        f->payload_size = n;
        l->pending_bytes = n;
    }
    l->pending_kind = f->kind;
    return 1;
}
int wn_direct_lane_accepted(struct wn_direct_lane *l)
{
    if (!valid(l))
        return -1;
    switch (l->pending_kind) {
    case WN_DIRECT_STATE:
        if (wn_direct_ack_written(&l->ack, l->pending_state))
            return -1;
        break;
    case WN_DIRECT_DATA:
        l->cursor += l->pending_bytes;
        break;
    case WN_DIRECT_FIN:
        l->fin_sent = true;
        break;
    default:
        return -1;
    }
    l->pending_kind = 0;
    l->pending_bytes = 0;
    return 0;
}
int wn_direct_lane_receive(struct wn_direct_lane *l, const struct wn_direct_frame *f, int64_t now)
{
    if (!valid(l) || !f || f->flow_id != l->id || !time_valid(l, now))
        return -1;
    int result;
    switch (f->kind) {
    case WN_DIRECT_DATA:
        if (!f->payload || !f->payload_size || f->payload_size > WN_DIRECT_MAX_DATA)
            return -1;
        result = wn_direct_receive(l->receiver, f->payload, f->payload_size);
        break;
    case WN_DIRECT_FIN:
        result = wn_direct_receive_finish(l->receiver, f->value);
        break;
    default:
        return -1;
    }
    return result ? -1 : wn_direct_ack_update(&l->ack, receipt(l->receiver), now);
}
int wn_direct_lane_state(struct wn_direct_lane *l, struct wn_direct_state_entry s)
{
    if (!valid(l) || s.flow_id != l->id || (s.fin_seen && !l->sender->finished) ||
        (l->fin_ack && !s.fin_seen))
        return -1;
    if (wn_direct_send_state(l->sender, s.received, s.limit))
        return -1;
    l->fin_ack = s.fin_seen;
    return 0;
}
int wn_direct_lane_grant(struct wn_direct_lane *l, uint64_t limit, int64_t now)
{
    if (!valid(l) || !time_valid(l, now) || limit < l->receiver->buffer.limit)
        return -1;
    if (wn_direct_reserve(&l->receiver->buffer, limit))
        return -1;
    return wn_direct_ack_update(&l->ack, receipt(l->receiver), now);
}
int wn_direct_lane_reattach(struct wn_direct_lane *l, const struct wn_direct_snapshot *remote,
                            int64_t now)
{
    if (!valid(l) || !remote || now < 0 || (l->fin_ack && !remote->receive_finished))
        return -1;
    struct wn_direct_snapshot local = wn_direct_snapshot(l->sender, l->receiver);
    struct wn_direct_reconciliation plan;
    if (wn_direct_reconcile(&local, remote, &plan))
        return -1;
    if (wn_direct_send_state(l->sender, plan.outgoing.received, plan.outgoing.limit))
        return -1;
    if (plan.incoming_finished && wn_direct_receive_finish(l->receiver, plan.incoming_final))
        return -1;
    l->cursor = plan.outgoing.received;
    l->fin_ack = plan.outgoing.fin_seen;
    l->fin_sent = false;
    l->pending_kind = 0;
    l->pending_bytes = 0;
    return wn_direct_ack_init(&l->ack, receipt(l->receiver), now);
}
