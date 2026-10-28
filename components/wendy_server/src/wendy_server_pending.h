#pragma once
#include <stdbool.h>
#include <stdint.h>

/* A physical client may wait without constructing TLS. Native VIP clients go
 * straight to the bounded mesh actor instead, so they can request its normal
 * handshake-workspace admission. The returned descriptor transfers ownership. */
struct wendy_server_pending { int fd; uint64_t deadline_ms; };
static inline bool wendy_server_pending_put(struct wendy_server_pending *p,
    int fd,uint64_t now)
{
    if(p->fd>=0)return false;
    p->fd=fd;p->deadline_ms=now+60000;return true;
}
static inline int wendy_server_pending_take(struct wendy_server_pending *p,
    bool ready,uint64_t now,bool *expired)
{
    *expired=p->fd>=0 && now>=p->deadline_ms;
    if(p->fd<0 || (!ready && !*expired))return -1;
    int fd=p->fd;p->fd=-1;p->deadline_ms=0;return fd;
}
