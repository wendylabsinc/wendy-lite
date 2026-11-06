/* SPDX-License-Identifier: Apache-2.0 */
#pragma once
#include "wendy_net_peer_protocol.h"
#include "wendy_net_alloc.h"
#include <limits.h>
#include <string.h>
#include <time.h>
#ifdef ESP_PLATFORM
#include "sdkconfig.h"
#endif
#if defined(ESP_PLATFORM) && defined(CONFIG_WENDY_NET_ENDPOINT_GATEWAY) && CONFIG_WENDY_NET_ENDPOINT_GATEWAY
#define WN_ROUTE_HANDOFF_ENABLED 0
#else
#define WN_ROUTE_HANDOFF_ENABLED 1
#endif
/* Detached, actor-owned authority only. No signed body, key DER or wire cache. */
struct wn_route_proof {
    struct wn_origin origin;
    int64_t deadline_us, path_deadline_us, issued, expires;
    time_t signing_not_before, issuer_not_before, not_after;
    uint8_t key[32], continuity[32];
};
struct wn_route_handoff {
    struct wn_route_proof current, prior;
    bool has_prior, current_verified, current_eligible, requested;
};
int wn_route_continuity(const struct wn_doc *, unsigned, uint8_t[32]);
static inline bool wnrh_later(uint16_t next, uint16_t old)
{
    uint16_t distance = (uint16_t)(next - old);
    return distance && distance < 32768;
}
static inline time_t wnrh_policy_at(time_t base, int64_t start, int64_t now)
{
    if (base <= 0 || start < 0 || now < start)
        return 0;
    int64_t elapsed = (now - start) / INT64_C(1000000);
    return (int64_t)base > INT64_MAX - elapsed ? 0 : (time_t)((int64_t)base + elapsed);
}
static inline int64_t wnrh_cap(time_t end, time_t base, int64_t now)
{
    if (end <= base || base <= 0 || now < 0)
        return now;
    int64_t seconds = (int64_t)end - base;
    return seconds > (INT64_MAX - now) / INT64_C(1000000)
               ? INT64_MAX : now + seconds * INT64_C(1000000);
}
static inline bool wnrh_window(const struct wn_route_proof *p, time_t leaf_start,
                                 time_t selected_end)
{
    return leaf_start >= 0 && selected_end > 0 &&
           leaf_start <= INT64_MAX / 1000 && selected_end <= INT64_MAX / 1000 &&
           p->issued >= (int64_t)leaf_start * 1000 &&
           p->expires <= (int64_t)selected_end * 1000;
}
static inline bool wnrh_refresh_proof(struct wn_route_proof *p, time_t base, int64_t now,
                                      bool uncertain)
{
    /* A known selected-path expiry permanently tightens its monotonic cap,
     * including a trusted forward jump past NotAfter. Static window failures
     * alone do not create a later eligibility lease. */
    if (base > 0 && now >= 0 && p->not_after > 0) {
        int64_t cap = wnrh_cap(p->not_after, base, now);
        if (cap < p->path_deadline_us)
            p->path_deadline_us = cap;
    }
    if (!wnrh_window(p, p->signing_not_before, p->not_after) || base <= 0 ||
        p->issuer_not_before > base || p->not_after <= base ||
        (p->signing_not_before > base &&
         (!uncertain || (int64_t)p->signing_not_before - base > INT64_C(86400))))
        return false;
    return p->path_deadline_us > now;
}
static inline bool wnrh_live(const struct wn_route_proof *p, int64_t now)
{
    return p->deadline_us > now && p->path_deadline_us > now;
}
static inline bool wnrh_current(struct wn_route_handoff *s, time_t base, int64_t now,
                                bool uncertain, time_t current_leaf_start,
                                time_t current_issuer_start, time_t current_selected_end)
{
    /* Signature/key validity is durable for this body. Date eligibility uses
     * the CURRENT independently verified same-key leaf, while original signer
     * dates remain in s->current for any future detached old proof. */
    if (!s)
        return false;
    if (base > 0 && now >= 0 && s->current.not_after > 0) {
        int64_t original_cap = wnrh_cap(s->current.not_after, base, now);
        if (original_cap < s->current.path_deadline_us)
            s->current.path_deadline_us = original_cap;
    }
    if (!s->current_verified || s->current.deadline_us <= now ||
        !wnrh_window(&s->current, current_leaf_start, current_selected_end))
        return false;
    struct wn_route_proof selected = s->current;
    selected.signing_not_before = current_leaf_start;
    selected.issuer_not_before = current_issuer_start;
    selected.not_after = current_selected_end < s->current.not_after ?
                             current_selected_end : s->current.not_after;
    if (!wnrh_refresh_proof(&selected, base, now, uncertain))
        return false;
    if (current_selected_end < s->current.not_after)
        s->current.not_after = current_selected_end;
    if (selected.path_deadline_us < s->current.path_deadline_us)
        s->current.path_deadline_us = selected.path_deadline_us;
    return wnrh_live(&s->current, now);
}
static inline void wnrh_refresh(struct wn_route_handoff *s, time_t base, int64_t now,
                                bool uncertain, time_t current_leaf_start,
                                time_t current_issuer_start, time_t current_selected_end)
{
    if (!s)
        return;
    s->current_eligible = wnrh_current(s, base, now, uncertain, current_leaf_start,
                                      current_issuer_start, current_selected_end);
    if (s->has_prior) {
        struct wn_route_proof held = s->prior;
        held.issuer_not_before = current_issuer_start;
        held.not_after = current_selected_end < s->prior.not_after ?
                             current_selected_end : s->prior.not_after;
        if (!s->current_eligible || !wnrh_window(&held, current_leaf_start, current_selected_end) ||
            !wnrh_refresh_proof(&held, base, now, uncertain) || !wnrh_live(&held, now))
            s->has_prior = false;
        else {
            if (current_selected_end < s->prior.not_after)
                s->prior.not_after = current_selected_end;
            if (held.path_deadline_us < s->prior.path_deadline_us)
                s->prior.path_deadline_us = held.path_deadline_us;
            s->prior.issuer_not_before = current_issuer_start;
        }
    }
}
static inline void wnrh_replace(struct wn_route_handoff *s, const struct wn_route_proof *next,
                                bool eligible, bool current_committed, int64_t now)
{
    bool continuous = eligible && s->current.deadline_us > now &&
                      s->current.origin.router_id == next->origin.router_id &&
                      !memcmp(s->current.continuity, next->continuity, 32);
    /* A valid retained proof stands on its own signature/window. An
     * intermediate pending publication need not fit a subsequently shortened
     * path for that older proof to remain valid under the new current path. */
    bool keep_prior = continuous && s->has_prior && wnrh_live(&s->prior, now) &&
                      !memcmp(s->prior.key, next->key, 32) &&
                      !memcmp(s->prior.continuity, next->continuity, 32) &&
                      s->prior.origin.router_id == next->origin.router_id &&
                      s->prior.issued >= (int64_t)next->signing_not_before * 1000 &&
                      s->prior.expires <= (int64_t)next->not_after * 1000 &&
                      wnrh_later(next->origin.seqno, s->prior.origin.seqno);
    if (!keep_prior) {
        bool capture = continuous && current_committed && s->current_verified &&
                       wnrh_live(&s->current, now) &&
                       !memcmp(s->current.key, next->key, 32) &&
                       s->current.issued >= (int64_t)next->signing_not_before * 1000 &&
                       s->current.expires <= (int64_t)next->not_after * 1000 &&
                       wnrh_later(next->origin.seqno, s->current.origin.seqno);
        if (capture) {
            s->prior = s->current;
            s->has_prior = true;
        } else
            s->has_prior = false;
    }
    if (s->has_prior) {
        if (next->not_after < s->prior.not_after)
            s->prior.not_after = next->not_after;
        s->prior.issuer_not_before = next->issuer_not_before;
    }
    bool keep_requested = keep_prior && s->requested &&
                          s->current.origin.router_id == next->origin.router_id &&
                          s->current.origin.seqno == next->origin.seqno;
    s->requested = keep_requested;
    s->current = *next;
    s->current_verified = true;
    s->current_eligible = true;
}
static inline void wnrh_resign(struct wn_route_handoff *s, const struct wn_route_proof *next)
{
    s->current_verified = true;
    s->current_eligible = true;
    if (memcmp(s->current.key, next->key, 32) ||
        (s->has_prior && (s->prior.issued < (int64_t)next->signing_not_before * 1000 ||
                          s->prior.expires > (int64_t)next->not_after * 1000)))
        s->has_prior = false;
    if (s->has_prior) {
        if (next->not_after < s->prior.not_after)
            s->prior.not_after = next->not_after;
        s->prior.issuer_not_before = next->issuer_not_before;
    }
    if (memcmp(s->current.key, next->key, 32))
        s->current.signing_not_before = next->signing_not_before;
    memcpy(s->current.key, next->key, 32);
    s->current.issuer_not_before = next->issuer_not_before;
    if (next->not_after < s->current.not_after)
        s->current.not_after = next->not_after;
    if (next->path_deadline_us < s->current.path_deadline_us)
        s->current.path_deadline_us = next->path_deadline_us;
}
