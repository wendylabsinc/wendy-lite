#include "wendy_net_direct_poll.h"
#include <assert.h>
static int upper_fd(void *arg)
{
    (void)arg;
    return 9;
}
int main(void)
{
    struct wn_direct_pool pool = {.available = 1};
    struct wn_direct_flow flows[2] = {
        {.id = 1,
         .has_lane = true,
         .promoted = true,
         .socket = {.fd = -1},
         .upper = {.fd = upper_fd},
         .receiver = {
             .finished = true, .final = 512, .buffer = {.pool = &pool, .end = 256, .limit = 512}}}};
    struct wn_direct_peer peer = {
        .session = {.active = true, .security_deadline = 1000000},
        .flows = {.slots = 1, .flows = flows, .window = 1024, .upper_control = true}};
    struct wn_direct_registry registry = {.peers = &peer};
    fd_set rd, wr;
    FD_ZERO(&rd);
    FD_ZERO(&wr);
    int maximum = 0;
    wn_direct_registry_pollfds(&registry, &rd, &wr, &maximum, 2000000);
    assert(FD_ISSET(9, &rd) && !FD_ISSET(9, &wr));
    flows[0].receiver.buffer.end = 512;
    FD_ZERO(&rd);
    FD_ZERO(&wr);
    maximum = 0;
    wn_direct_registry_pollfds(&registry, &rd, &wr, &maximum, 2000000);
    assert(!FD_ISSET(9, &rd));
    return 0;
}
