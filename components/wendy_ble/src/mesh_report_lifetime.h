/* SPDX-License-Identifier: Apache-2.0 */
#pragma once
#include <stdatomic.h>
#include <stdbool.h>
#include <limits.h>

/* One callback publication gate. Closing prevents new borrowed contexts;
 * already borrowed contexts must return before their owner may be destroyed. */
struct wble_report_lifetime { atomic_uint state; };
#define WBLE_REPORT_OPEN (UINT_MAX ^ (UINT_MAX >> 1))
static inline void wble_report_open(struct wble_report_lifetime *l)
{ atomic_store_explicit(&l->state,WBLE_REPORT_OPEN,memory_order_release); }
static inline bool wble_report_acquire(struct wble_report_lifetime *l)
{
    unsigned value=atomic_load_explicit(&l->state,memory_order_acquire);
    while(value&WBLE_REPORT_OPEN){
        if((value&~WBLE_REPORT_OPEN)==WBLE_REPORT_OPEN-1)return false;
        if(atomic_compare_exchange_weak_explicit(&l->state,&value,value+1,
                memory_order_acquire,memory_order_relaxed))return true;
    }
    return false;
}
static inline void wble_report_close(struct wble_report_lifetime *l)
{ atomic_fetch_and_explicit(&l->state,~WBLE_REPORT_OPEN,memory_order_acq_rel); }
static inline void wble_report_release(struct wble_report_lifetime *l)
{ atomic_fetch_sub_explicit(&l->state,1,memory_order_release); }
static inline bool wble_report_drained(const struct wble_report_lifetime *l)
{ return !(atomic_load_explicit(&l->state,memory_order_acquire)&~WBLE_REPORT_OPEN); }
