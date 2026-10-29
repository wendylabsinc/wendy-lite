#pragma once
#include "mdns.h"
#include <stdbool.h>
#include <stdint.h>
struct wnm_advertisement {
    bool enabled;
    char instance[56],principal[106],mesh[17],radio[40],psm[6];
};
struct wnm_intent {
    struct wnm_advertisement advertisement;
    bool browse;
    char tenant[37],self[65];
};
struct wnm_owner;
struct wnm_owner *wnm_open(mdns_query_notify_t notify);
/* Only call from the actor. No SDK calls or waits occur in these operations. */
void wnm_collect(struct wnm_owner *);
bool wnm_results(struct wnm_owner *,mdns_result_t **,const char **tenant,const char **self);
void wnm_consumed(struct wnm_owner *);
void wnm_drive(struct wnm_owner *,const struct wnm_intent *,int64_t now);
int64_t wnm_deadline(const struct wnm_owner *);
bool wnm_idle(const struct wnm_owner *);
/* Returns false while an SDK handle, advertisement or worker loan remains. */
bool wnm_close(struct wnm_owner *);
