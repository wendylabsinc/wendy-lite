#include "wendy_net_direct_recovery_plan.h"
#include <string.h>
static bool unopened(const struct wn_direct_snapshot *s)
{
    return !s->acked && !s->offered && !s->tail && !s->consumed && !s->received &&
           !s->send_finished && !s->receive_finished;
}
static int namespaces(const struct wn_direct_recovery_view *local,
                      const struct wn_direct_recovery_view *remote, uint8_t role)
{
    for (unsigned ns = 0; ns < 2; ns++) {
        const struct wn_direct_recovery_view *opener = ns == role ? local : remote,
                                             *receiver = ns == role ? remote : local;
        const struct wn_direct_namespace_checkpoint *a = &opener->namespaces[ns],
                                                    *b = &receiver->namespaces[ns];
        if (a->admitted < b->admitted || a->high_water < b->high_water || a->grant > b->grant ||
            ((a->admitted == b->admitted) != (a->high_water == b->high_water)))
            return -1;
        uint64_t unseen = 0;
        for (size_t i = 0; i < opener->count; i++) {
            const struct wn_direct_recovery_record *r = &opener->records[i];
            if ((r->id & 1) == ns && r->id > b->high_water) {
                if (r->open_complete || !unopened(&r->flow))
                    return -1;
                unseen++;
            }
        }
        if (unseen != a->admitted - b->admitted)
            return -1;
    }
    return 0;
}
static int walk(const struct wn_direct_recovery_view *local,
                const struct wn_direct_recovery_view *remote, uint8_t role,
                struct wn_direct_recovery_step *out, size_t *count)
{
    size_t i = 0, j = 0, n = 0;
    while (i < local->count || j < remote->count) {
        struct wn_direct_recovery_step step = {0};
        const struct wn_direct_recovery_record *a = i < local->count ? &local->records[i] : NULL,
                                               *b = j < remote->count ? &remote->records[j] : NULL;
        if (!b || (a && a->id < b->id)) {
            step.id = a->id;
            step.action = WN_DIRECT_REPLAY_OPEN;
            step.open_complete = a->open_complete;
            step.result = a->result;
            step.reset = a->reset;
            step.reset_code = a->reset_code;
            if (a->id <= remote->namespaces[a->id & 1].high_water) {
                if (!a->local_closed)
                    return -1;
                step.action = WN_DIRECT_RETIRE;
            } else if ((a->id & 1) != role || a->open_complete || !unopened(&a->flow))
                return -1;
            i++;
        } else if (!a || b->id < a->id) {
            step.id = b->id;
            step.action = WN_DIRECT_RECEIVE_OPEN;
            step.open_complete = b->open_complete;
            step.result = b->result;
            step.reset = b->reset;
            step.reset_code = b->reset_code;
            if (b->id <= local->namespaces[b->id & 1].high_water) {
                if (!b->local_closed)
                    return -1;
                step.action = WN_DIRECT_CONFIRM_RETIRED;
            } else if ((b->id & 1) == role || b->open_complete || !unopened(&b->flow))
                return -1;
            j++;
        } else {
            if (memcmp(a->open_digest, b->open_digest, 32) ||
                (a->remote_closed && !b->local_closed) || (b->remote_closed && !a->local_closed))
                return -1;
            const struct wn_direct_recovery_record *opener = (a->id & 1) == role ? a : b,
                                                   *receiver = (a->id & 1) == role ? b : a;
            if ((opener->open_complete && !receiver->open_complete) ||
                (opener->open_complete && opener->result != receiver->result))
                return -1;
            step.id = a->id;
            step.open_complete = receiver->open_complete;
            step.result = receiver->result;
            if (a->reset || b->reset) {
                step.action = WN_DIRECT_RESET_FLOW;
                step.reset = true;
                step.reset_code = a->reset ? a->reset_code : b->reset_code;
            } else {
                if ((!receiver->open_complete || receiver->result) &&
                    (!unopened(&a->flow) || !unopened(&b->flow)))
                    return -1;
                if (wn_direct_reconcile(&a->flow, &b->flow, &step.flow))
                    return -1;
            }
            i++;
            j++;
        }
        if (out)
            out[n] = step;
        n++;
    }
    *count = n;
    return 0;
}
int wn_direct_recovery_validate(const struct wn_direct_recovery_view *local,
                                const struct wn_direct_recovery_view *remote, uint8_t role)
{
    size_t count;
    if (role > 1 || !wn_direct_recovery_view_valid(local) ||
        !wn_direct_recovery_view_valid(remote) || namespaces(local, remote, role))
        return -1;
    return walk(local, remote, role, NULL, &count);
}
int wn_direct_recovery_plan(const struct wn_direct_recovery_view *local,
                            const struct wn_direct_recovery_view *remote, uint8_t role,
                            struct wn_direct_recovery_step *out, size_t capacity, size_t *count)
{
    if (!count)
        return -1;
    *count = 0;
    if (role > 1 || !wn_direct_recovery_view_valid(local) ||
        !wn_direct_recovery_view_valid(remote) || namespaces(local, remote, role))
        return -1;
    size_t needed = 0;
    if (walk(local, remote, role, NULL, &needed) || needed > capacity || (needed && !out))
        return -1;
    return walk(local, remote, role, out, count);
}
