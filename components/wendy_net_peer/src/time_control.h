#pragma once
#include "wendy_net_peer_protocol.h"
#include <stdatomic.h>
#include "wendy_net_memory.h"
/* One public nonce request/reply, allocated only for an active renewal. */
struct wnt_job {
    atomic_uint references;
    atomic_bool done;
    uint64_t id;
    int64_t deadline;
    uint8_t query[128], *reply;
    size_t query_size,size,offset;
    int result;
    bool sent,started,reply_external;
    wendy_net_memory_reservation_t reply_charge;
};
struct wnt_job *wnt_new(uint64_t id,const void *,size_t,int64_t deadline);
void wnt_retain(struct wnt_job *);
void wnt_release(struct wnt_job *);
int wnt_request_write(const struct wnt_job *,char *,size_t);
int wnt_reply_write(const struct wnt_job *,char *,size_t);
struct wnt_job *wnt_request_read(const struct wn_doc *,unsigned,int64_t deadline);
int wnt_reply_read(struct wnt_job *,const struct wn_doc *,unsigned);
