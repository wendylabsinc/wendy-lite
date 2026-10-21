#include "wendy_mesh_discovery.h"
#include "mdns.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static const char tenant[] = "11111111-1111-4111-8111-111111111111";
static const char self[] = "22222222-2222-4222-8222-222222222222";
static const char peer[] = "33333333-3333-4333-8333-333333333333";
static char principal[106];
static mdns_result_t *reply;
static int query_error, freed, random_calls;
int mdns_query_ptr(const char *service, const char *proto, uint32_t timeout, size_t max, mdns_result_t **out)
{
    assert(!strcmp(service, "_wendy-mesh") && !strcmp(proto, "_tcp"));
    assert(timeout == 2000 && max == 16);
    *out = reply;
    return query_error;
}
void mdns_query_results_free(mdns_result_t *p) { assert(p == reply); ++freed; }
uint32_t esp_random(void) { ++random_calls; return 0; }
int main(void)
{
    snprintf(principal, sizeof principal, "spiffe://wendy.sh/tenant/%s/device/%s", tenant, peer);
    uint8_t ip[4] = {192, 168, 100, 110};
    struct wm_discovered_peer candidate, out[WM_DISCOVERY_MAX + 1];
    assert(!wm_discovery_candidate(tenant, self, principal, ip, &candidate));
    assert(!strcmp(candidate.host, "192.168.100.110") && !strcmp(candidate.device, peer));
    assert(wm_discovery_candidate(self, self, principal, ip, &candidate));
    assert(wm_discovery_candidate(tenant, peer, principal, ip, &candidate));
    assert(wm_discovery_candidate(tenant, self, NULL, ip, &candidate));
    for (unsigned i = 0; i < 4; ++i) {
        uint8_t bad[4][4] = {{0,1,2,3}, {127,0,0,1}, {224,0,0,1}, {169,254,0,1}};
        assert(wm_discovery_candidate(tenant, self, principal, bad[i], &candidate));
    }
    mdns_txt_item_t txt[2] = {{"principal", principal}, {"principal", principal}};
    uint8_t lengths[2] = {105, 105};
    mdns_ip_addr_t addr[10] = {0};
    for (size_t i = 0; i < 10; ++i) {
        ip[3] = 110 + i;
        memcpy(&addr[i].addr.u_addr.ip4.addr, ip, 4);
        if (i < 9) addr[i].next = &addr[i+1];
    }
    mdns_result_t result = {.ttl=120, .port=43023, .txt=txt, .txt_count=1, .txt_value_len=lengths, .addr=addr};
    reply = &result;
    memset(out, 0xa5, sizeof out);
    assert(wm_discover_peers(tenant, self, out) == WM_DISCOVERY_MAX);
    assert(random_calls == WM_DISCOVERY_MAX - 1 && freed == 1);
    assert((unsigned char)out[WM_DISCOVERY_MAX].host[0] == 0xa5);
    assert(strcmp(out[0].host, "192.168.100.110")); // randomized order
    addr[0].next = &addr[1]; addr[1].next = NULL;
    addr[1].addr = addr[0].addr;
    assert(wm_discover_peers(tenant, self, out) == 1); // duplicates
    result.txt_count = 2;
    assert(!wm_discover_peers(tenant, self, out));
    result.txt_count = 1; lengths[0] = 104;
    assert(!wm_discover_peers(tenant, self, out));
    lengths[0] = 105; result.ttl = 0;
    assert(!wm_discover_peers(tenant, self, out));
    result.ttl = 120; result.port = 1234;
    assert(!wm_discover_peers(tenant, self, out));
    result.port = 43023; addr[0].addr.type = addr[1].addr.type = 6;
    assert(!wm_discover_peers(tenant, self, out));
    query_error = -1;
    assert(!wm_discover_peers(tenant, self, out) && freed == 8);
    puts("discovery: tenant/self filtering, address validation, bounds, deduplication, shuffle and malformed records passed");
    return 0;
}
