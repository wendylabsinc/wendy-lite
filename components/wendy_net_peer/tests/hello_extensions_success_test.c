/* Additive hello fields preserve the version1 identity/capacity contract. */
#include "wendy_net_control.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    static const char self[] = "00000000-0000-4000-8000-000000000001";
    static const char peer[] = "00000000-0000-4000-8000-000000000002";
    char original[512], extended[512];
    int n = wn_router_hello_write(peer, self, original, sizeof original);
    assert(n > 0 && !wn_router_hello_check(original, (size_t)n, self, peer));
    struct wn_doc doc;
    assert(!wn_doc_parse(&doc, original, (size_t)n));
    const struct wn_token *hello = wn_doc_token(&doc, wn_doc_member(&doc, 0, "hello"));
    assert(hello && hello->end == (unsigned)n && (uint8_t)original[hello->start] == 0xa5);
    memcpy(extended, original, (size_t)n);
    extended[0] = (char)0xa3;            /* Add one top-level field. */
    extended[hello->start] = (char)0xa6; /* Add one nested hello field. */
    const uint8_t additions[] = {0x61, 'x', 0xa1, 0x61, 'f', 0xf5, 0x61, 'y', 0x82, 0x01, 0x02};
    memcpy(extended + n, additions, sizeof additions);
    size_t size = (size_t)n + sizeof additions;
    assert(!wn_router_hello_check(extended, size, self, peer));
    assert(wn_router_hello_check(extended, size, peer, self));
    assert(!wn_doc_parse(&doc, extended, size));
    int h = wn_doc_member(&doc, 0, "hello");
    const struct wn_token *version =
        wn_doc_token(&doc, wn_doc_member(&doc, (unsigned)h, "version"));
    assert(version && (uint8_t)extended[version->start] == 1);
    extended[version->start] = 2;
    assert(wn_router_hello_check(extended, size, self, peer));
    extended[version->start] = 1;
    const struct wn_token *mtu = wn_doc_token(&doc, wn_doc_member(&doc, (unsigned)h, "mtu"));
    assert(mtu && mtu->header == 3);
    extended[mtu->start + 2] ^= 1;
    assert(wn_router_hello_check(extended, size, self, peer));
    extended[mtu->start + 2] ^= 1;
    /* A duplicate required field remains invalid, rather than last-wins. */
    extended[0] = (char)0xa4;
    memcpy(extended + size, (uint8_t[]){0x61, 'k', 0x61, 'x'}, 4);
    assert(wn_router_hello_check(extended, size + 4, self, peer));
    puts("hello extensions ignored; version, identity, capacity and duplicate checks preserved");
    return 0;
}
