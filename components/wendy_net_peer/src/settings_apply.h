/* Bounded management response handoff. Pure state; caller owns serialization. */
#pragma once
#include <stdbool.h>
#include <stdint.h>
struct wnsa {uint32_t sequence,token;int64_t started,reply_at;bool replied;};
static inline uint32_t wnsa_begin(struct wnsa *s,int64_t now)
{
    if(s->token)return 0;
    s->sequence=(s->sequence+1)&UINT32_C(0x7fffffff);if(!s->sequence)++s->sequence;
    s->token=s->sequence;s->started=now;s->reply_at=0;s->replied=false;return s->token;
}
static inline void wnsa_reply(struct wnsa *s,uint32_t token,int64_t now)
{if(token && token==s->token && !s->replied){s->reply_at=now;s->replied=true;}}
static inline bool wnsa_poll(struct wnsa *s,int64_t now,bool network_drained)
{
    if(!s->token)return false;
    /* Give the outer IP/carrier driver a scheduling interval after the native
     * TLS fence. Continuous unrelated traffic cannot postpone settings forever.
     * A vanished client also cannot retain the old policy indefinitely. */
    bool ready=s->replied ? now-s->reply_at>=INT64_C(250000) &&
        (network_drained || now-s->reply_at>=INT64_C(5000000)):
        now-s->started>=INT64_C(45000000);
    if(ready)s->token=0;
    return ready;
}
