#pragma once
#include <stdint.h>

#if defined(__wasm__)
#define WENDY_SERVICE_IMPORT(name) __attribute__((import_module("wendy"), import_name(name)))
#else
#define WENDY_SERVICE_IMPORT(name)
#endif
WENDY_SERVICE_IMPORT("services_epoch") int services_epoch(void);
WENDY_SERVICE_IMPORT("services_publish") int services_publish(const void *,int);
WENDY_SERVICE_IMPORT("services_withdraw") int services_withdraw(const void *,int);
WENDY_SERVICE_IMPORT("services_browse") int services_browse(const void *,int,char *,int);
WENDY_SERVICE_IMPORT("services_browse_endpoints") int services_browse_endpoints(const void *,int,char *,int);
#undef WENDY_SERVICE_IMPORT

/* This state and the retained declaration belong to the guest, never to host
 * mesh heap. Zero-initialize one state per desired service. Poll from the
 * guest's normal event loop; the helper bounds native checks/retries to once
 * per second. No payload pointer is retained by the host. */
typedef struct {
    uint64_t next_check_ms;
    uint32_t epoch;
    int32_t last_result;
} wendy_service_replay;

static inline void wendy_service_replay_changed(wendy_service_replay *state)
{
    state->epoch=0;state->next_check_ms=0;state->last_result=-2;
}

/* 0 means registered in the observed incarnation (or withdrawn). -2 means
 * pending/off; other results are the native validation/admission result.
 * A successful native call is acknowledged only if its incarnation survived
 * the call. A concurrent restart therefore leaves intent pending for replay.
 * For withdrawal, pass the service ID instead of its JSON declaration. */
static inline int wendy_service_replay_step(wendy_service_replay *state,
    const void *input,int size,int withdrawing,uint64_t now_ms)
{
    if(now_ms<state->next_check_ms)return state->last_result;
    state->next_check_ms=now_ms+1000;
    uint32_t epoch=(uint32_t)services_epoch();
    if(!epoch){state->epoch=0;return state->last_result=-2;}
    if(!withdrawing && state->epoch==epoch)return state->last_result=0;
    int result=withdrawing ? services_withdraw(input,size):services_publish(input,size);
    uint32_t after=(uint32_t)services_epoch();
    if(result==0 && epoch==after){state->epoch=epoch;return state->last_result=0;}
    state->epoch=0;
    return state->last_result=result==0 ? -2:result;
}
