#pragma once
#include <stddef.h>
/* Caller serializes access. Only queued packets own bytes; init/reset retain
 * no maximum-sized payload allocation. Positive push result is backpressure. */
struct wnpq_packet;
struct wnpq {
    struct wnpq_packet *head,*tail;
    size_t count,limit;
    void *(*allocate)(size_t);
    void (*release)(void *);
};
void wnpq_init(struct wnpq *,size_t limit,void *(*allocate)(size_t),void (*release)(void *));
int wnpq_push(struct wnpq *,const void *,size_t);
/* Borrow the head until drop/reset. The caller keeps its serialization lock
 * while inspecting/submitting it, so downstream backpressure retains bytes. */
void *wnpq_front(struct wnpq *,size_t *);
void wnpq_drop(struct wnpq *);
/* out has room for one WN_MTU-sized packet. Returns1 when copied,0 if empty. */
int wnpq_pop(struct wnpq *,void *out,size_t *size);
void wnpq_reset(struct wnpq *);
