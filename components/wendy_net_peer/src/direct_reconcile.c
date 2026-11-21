#include "wendy_net_direct_reconcile.h"
#include <string.h>
struct wn_direct_snapshot wn_direct_snapshot(const struct wn_direct_sender *s,
                                             const struct wn_direct_receiver *r)
{
    return (struct wn_direct_snapshot){.acked = s->buffer.start,
                                       .offered = s->offered,
                                       .tail = s->buffer.end,
                                       .remote_limit = s->remote_limit,
                                       .consumed = r->buffer.start,
                                       .received = r->buffer.end,
                                       .limit = r->buffer.limit,
                                       .send_final = s->final,
                                       .receive_final = r->final,
                                       .send_finished = s->finished,
                                       .receive_finished = r->finished};
}
bool wn_direct_snapshot_valid(const struct wn_direct_snapshot *s)
{
    return s && s->acked <= s->offered && s->offered <= s->tail && s->offered <= s->remote_limit &&
           s->consumed <= s->received && s->received <= s->limit &&
           ((!s->send_finished && !s->send_final) ||
            (s->send_finished && s->send_final == s->tail)) &&
           ((!s->receive_finished && !s->receive_final) ||
            (s->receive_finished && s->receive_final >= s->received));
}
static bool consistent(const struct wn_direct_snapshot *s, const struct wn_direct_snapshot *r)
{
    return r->received >= s->acked && r->received <= s->offered && r->limit >= s->remote_limit &&
           (!r->receive_finished || (s->send_finished && r->receive_final == s->send_final));
}
int wn_direct_reconcile(const struct wn_direct_snapshot *local,
                        const struct wn_direct_snapshot *remote,
                        struct wn_direct_reconciliation *out)
{
    if (!out)
        return WN_DIRECT_BOUNDS;
    memset(out, 0, sizeof *out);
    if (!local || !remote || !wn_direct_snapshot_valid(local) ||
        !wn_direct_snapshot_valid(remote) || !consistent(local, remote) ||
        !consistent(remote, local))
        return WN_DIRECT_BOUNDS;
    *out = (struct wn_direct_reconciliation){
        .outgoing = {remote->received, remote->limit, remote->receive_finished},
        .incoming_final = remote->send_final,
        .incoming_finished = remote->send_finished,
        .replay_fin = local->send_finished && !remote->receive_finished};
    return 0;
}
