#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>
/* One actor-owned effect; only complete() runs on the TCP/IP thread. The
 * submitted target stays immutable until completion has been acknowledged. */
enum wnne_target {WNNE_REMOVED,WNNE_DOWN,WNNE_UP};
struct wnne_effect {
    enum wnne_target desired,applied,submitted;
    atomic_bool done;
    bool pending;
    int result;
    int64_t retry_at;
};
void wnne_init(struct wnne_effect *,enum wnne_target applied);
void wnne_desire(struct wnne_effect *,enum wnne_target);
/* True requests one outer nonblocking submit. Always call submitted() after. */
bool wnne_next(struct wnne_effect *,int64_t now);
void wnne_submitted(struct wnne_effect *,bool accepted,int64_t now);
void wnne_complete(struct wnne_effect *,int result);
bool wnne_idle(const struct wnne_effect *);
int64_t wnne_deadline(const struct wnne_effect *);
