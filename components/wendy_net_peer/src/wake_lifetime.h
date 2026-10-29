#pragma once
#include <stdatomic.h>
#include <stdbool.h>

/* A completion may wake after publishing its result. Keep the numeric fd
 * alive until every publisher that could have observed it has returned. */
struct wnad_wake_lifetime {
    atomic_int descriptor;
    atomic_uint publishers;
};
static inline int wnad_wake_borrow(struct wnad_wake_lifetime *wake)
{
    atomic_fetch_add(&wake->publishers,1);
    return atomic_load(&wake->descriptor);
}
static inline void wnad_wake_return(struct wnad_wake_lifetime *wake)
{atomic_fetch_sub(&wake->publishers,1);}
static inline int wnad_wake_detach(struct wnad_wake_lifetime *wake)
{return atomic_exchange(&wake->descriptor,-1);}
static inline bool wnad_wake_drained(struct wnad_wake_lifetime *wake)
{return atomic_load(&wake->publishers)==0;}
