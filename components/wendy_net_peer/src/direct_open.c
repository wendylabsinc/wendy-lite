#include "wendy_net_direct_open.h"
#include <string.h>
int wn_direct_opens_init(struct wn_direct_opens *r, uint16_t count, bool peer_coordinator)
{
    if (!r || !count)
        return WN_DIRECT_BOUNDS;
    *r = (struct wn_direct_opens){
        .count = count, .free = count, .parity = peer_coordinator ? 0 : 1};
    return 0;
}
int wn_direct_opens_grant(struct wn_direct_opens *r, uint64_t through)
{
    if (!r || through < r->grant || through < r->admitted || through - r->admitted > r->free)
        return WN_DIRECT_BOUNDS;
    r->grant = through;
    return 0;
}
int wn_direct_opens_peer_grant(struct wn_direct_opens *r, uint64_t through)
{
    if (!r || through < r->grant || through < r->admitted)
        return WN_DIRECT_BOUNDS;
    r->grant = through;
    return 0;
}
int wn_direct_opens_admit(struct wn_direct_opens *r, uint32_t id)
{
    if (!r || !id || (id & 1) != r->parity)
        return WN_DIRECT_BOUNDS;
    if (id <= r->high_water)
        return WN_DIRECT_RETIRED;
    if (r->admitted >= r->grant || !r->free)
        return WN_DIRECT_CAPACITY;
    r->high_water = id;
    r->admitted++;
    r->free--;
    return 0;
}
