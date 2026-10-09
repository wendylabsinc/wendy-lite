#include "../components/wendy_server/src/wendy_peer_identity.h"
#include <assert.h>
#include <stdio.h>

#define ROOT "spiffe://wendy.sh/tenant/12345678-1234-1234-1234-123456789abc/"
int main(void)
{
    struct { const char *uri; const char *kind; bool valid; } cases[] = {
        {ROOT "operator/alice", "operator", true},
        {ROOT "operator/alice@example.com", "operator", true},
        {ROOT "device/board-1", "device", true},
        {ROOT "device/board-1", "operator", false},
        {ROOT "service/user-alice", "operator", false},
        {ROOT "operator/alice", "device", false},
        {ROOT "operator/", "operator", false},
        {ROOT "operator/alice/extra", "operator", false},
        {ROOT "operator/alice?admin=true", "operator", false},
        {ROOT "operator/alice#admin", "operator", false},
        {ROOT "operator/alice%2fadmin", "operator", false},
        {ROOT "operator/alice bob", "operator", false},
        {"urn:wendy:org:7:user:alice", "operator", false},
        {"spiffe://evil/tenant/12345678-1234-1234-1234-123456789abc/operator/alice", "operator", false},
        {"spiffe://wendy.sh/tenant/12345678x1234-1234-1234-123456789abc/operator/alice", "operator", false},
        {"spiffe://wendy.sh/tenant/12345678-1234-1234-1234-123456789abz/operator/alice", "operator", false},
        {"spiffe://wendy.sh/tenant/", "operator", false},
        {"", "operator", false},
    };
    unsigned char tenant[36];
    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
        assert(wendy_peer_identity((const unsigned char *)cases[i].uri, strlen(cases[i].uri),
                                   cases[i].kind, tenant) == cases[i].valid);
        if (cases[i].valid) assert(memcmp(tenant, "12345678-1234-1234-1234-123456789abc", 36) == 0);
    }
    // Include the NUL and tail in the SAN's actual length; it cannot hide a suffix.
    const unsigned char embedded[] = ROOT "operator/alice\0/other";
    assert(!wendy_peer_identity(embedded, sizeof(embedded) - 1, "operator", tenant));
    const unsigned char valid[] = ROOT "operator/alice";
    for (size_t size = 0; size < sizeof(ROOT "operator/") - 1; size++)
        assert(!wendy_peer_identity(valid, size, "operator", tenant));
    puts("20 operator identity tests passed");
}
