/* SPDX-License-Identifier: Apache-2.0 */
#pragma once
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

enum wble_gap_action { WBLE_GAP_INIT=1, WBLE_GAP_SCAN=2, WBLE_GAP_DIAL=4, WBLE_GAP_STOP=8 };
/* Error-only pacing: no first-attempt or successful path is delayed. */
#define WBLE_GAP_RETRY_US INT64_C(1000000)
struct wble_gap_retry { atomic_int_fast64_t at; };
static inline bool wble_gap_retry_due(const struct wble_gap_retry *r,int64_t now)
{return now>=atomic_load_explicit(&r->at,memory_order_acquire);}
static inline void wble_gap_retry_failed(struct wble_gap_retry *r,int64_t now)
{atomic_store_explicit(&r->at,now+WBLE_GAP_RETRY_US,memory_order_release);}
static inline void wble_gap_retry_clear(struct wble_gap_retry *r)
{atomic_store_explicit(&r->at,0,memory_order_release);}
static inline int64_t wble_gap_retry_deadline(const struct wble_gap_retry *r,int64_t now)
{int64_t at=atomic_load_explicit(&r->at,memory_order_acquire);return at>now ? at:INT64_MAX;}
struct wble_gap_dial { uint8_t address[6],type;uint16_t psm;uint32_t epoch; };
struct wble_gap_command { enum wble_gap_action action;struct wble_gap_dial dial; };
struct wble_gap_retirement { uint16_t handle;bool used,sent; };
static inline struct wble_gap_retirement *wble_gap_retiring_add(
    struct wble_gap_retirement *entries,unsigned count,uint16_t handle)
{
    struct wble_gap_retirement *empty=NULL;
    for(unsigned i=0;i<count;i++){
        if(entries[i].used && entries[i].handle==handle)return &entries[i];
        if(!entries[i].used)empty=&entries[i];
    }
    if(empty)*empty=(struct wble_gap_retirement){.handle=handle,.used=true};
    return empty;
}
static inline void wble_gap_retiring_done(struct wble_gap_retirement *entries,unsigned count,uint16_t handle)
{for(unsigned i=0;i<count;i++)if(entries[i].used && entries[i].handle==handle)entries[i].used=false;}
static inline bool wble_gap_retiring_busy(const struct wble_gap_retirement *entries,unsigned count)
{for(unsigned i=0;i<count;i++)if(entries[i].used)return true;return false;}
/* Only one immutable dial and coalesced scan/stop flags. Neither producer nor
 * host consumer waits behind a preempted publisher. The successful publisher
 * posts the host event after releasing this short metadata gate. */
struct wble_gap_effect {
    atomic_flag gate;
    atomic_uint pending,error;
    struct wble_gap_dial dial;
};
static inline void wble_gap_effect_init(struct wble_gap_effect *e)
{atomic_flag_clear(&e->gate);atomic_init(&e->pending,0);atomic_init(&e->error,0);memset(&e->dial,0,sizeof e->dial);}
static inline bool wble_gap_submit(struct wble_gap_effect *e,enum wble_gap_action action,
                                 const struct wble_gap_dial *dial)
{
    if(atomic_flag_test_and_set_explicit(&e->gate,memory_order_acquire))return false;
    unsigned pending=atomic_load_explicit(&e->pending,memory_order_relaxed);
    bool accepted=action==WBLE_GAP_STOP || !(pending&WBLE_GAP_STOP);
    if(action==WBLE_GAP_DIAL && (!dial || (pending&WBLE_GAP_DIAL)))accepted=false;
    if(accepted){
        if(action==WBLE_GAP_DIAL)e->dial=*dial;
        pending=action==WBLE_GAP_STOP ? WBLE_GAP_STOP:pending|action;
        atomic_store_explicit(&e->pending,pending,memory_order_release);
    }
    atomic_flag_clear_explicit(&e->gate,memory_order_release);return accepted;
}
static inline bool wble_gap_take(struct wble_gap_effect *e,struct wble_gap_command *out)
{
    if(atomic_flag_test_and_set_explicit(&e->gate,memory_order_acquire))return false;
    unsigned pending=atomic_load_explicit(&e->pending,memory_order_relaxed);
    unsigned action=pending&WBLE_GAP_STOP ? WBLE_GAP_STOP:
        pending&WBLE_GAP_INIT ? WBLE_GAP_INIT:pending&WBLE_GAP_DIAL ? WBLE_GAP_DIAL:
        pending&WBLE_GAP_SCAN ? WBLE_GAP_SCAN:0;
    if(action){out->action=(enum wble_gap_action)action;out->dial=e->dial;
        atomic_store_explicit(&e->pending,pending&~action,memory_order_release);}
    atomic_flag_clear_explicit(&e->gate,memory_order_release);return action!=0;
}
static inline void wble_gap_complete(struct wble_gap_effect *e,enum wble_gap_action action,int error)
{
    /* Preserve the first uncollected error if another normal command succeeds
     * before the actor runs. NimBLE/ESP error values fit the lower24bits. */
    if(error){unsigned empty=0;atomic_compare_exchange_strong(&e->error,&empty,
        ((unsigned)action<<24)|((unsigned)error&0xffffff));}
}
static inline int wble_gap_error(struct wble_gap_effect *e,unsigned *action)
{unsigned value=atomic_exchange(&e->error,0);if(action)*action=value>>24;return (int32_t)(value<<8)>>8;}
