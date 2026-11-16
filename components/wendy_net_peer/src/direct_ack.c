#include "wendy_net_direct_ack.h"
#include <string.h>
static bool same(struct wn_direct_receipt a, struct wn_direct_receipt b)
{
    return a.received == b.received && a.limit == b.limit && a.fin_seen == b.fin_seen;
}
int wn_direct_ack_init(struct wn_direct_ack *a, struct wn_direct_receipt s, int64_t now)
{
    if (!a || now < 0 || s.received > s.limit)
        return -1;
    memset(a, 0, sizeof *a);
    a->current = s;
    a->since = now;
    a->pending = true;
    a->initial = true;
    return 0;
}
int wn_direct_ack_update(struct wn_direct_ack *a, struct wn_direct_receipt s, int64_t now)
{
    if (!a || now < 0 || (a->pending && now < a->since) || s.received > s.limit ||
        s.received < a->current.received || s.limit < a->current.limit ||
        (a->current.fin_seen && !s.fin_seen))
        return -1;
    if (same(s, a->current))
        return 0;
    a->current = s;
    if (!a->pending) {
        a->pending = true;
        a->since = now;
    }
    return 0;
}
bool wn_direct_ack_due(const struct wn_direct_ack *a, int64_t now, struct wn_direct_receipt *out)
{
    if (!a || !out)
        return false;
    *out = a->current;
    /* Local delivery can advance current.limit while the sender still has
     * an exhausted advertised limit. Do not delay reopening that window. */
    return a->pending &&
           (a->initial || (a->current.fin_seen && !a->sent.fin_seen) ||
            a->current.received - a->sent.received >= WN_DIRECT_ACK_BYTES ||
            a->current.limit - a->sent.limit >= WN_DIRECT_CREDIT_BYTES ||
            (a->current.received >= a->sent.limit &&
             (a->current.received > a->sent.received || a->current.limit > a->sent.limit)) ||
            (now >= a->since && now - a->since >= WN_DIRECT_ACK_DELAY_US));
}
int wn_direct_ack_written(struct wn_direct_ack *a, struct wn_direct_receipt s)
{
    if (!a || s.received > s.limit || s.received < a->sent.received || s.limit < a->sent.limit ||
        s.received > a->current.received || s.limit > a->current.limit ||
        (a->sent.fin_seen && !s.fin_seen) || (s.fin_seen && !a->current.fin_seen))
        return -1;
    a->sent = s;
    a->initial = false;
    a->pending = !same(a->current, a->sent);
    return 0;
}
