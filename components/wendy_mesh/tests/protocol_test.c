#include "wendy_mesh_protocol.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    const char *device = "12345678-9abc-4def-8123-000000000002",
               *tenant = "12345678-9abc-4def-8123-000000000001";
    struct wm_manifest m = { .revision = UINT64_MAX,
        .router_id = UINT64_MAX - 1,
        .seqno = 65535,
        .issued = INT64_C(1800000000000),
        .expires = INT64_C(1800000060000),
        .agent_port = 5054 },
                       parsed;
    assert(!wm_uuid_parse(device, m.device));
    char text[768], principal[106], id[37];
    uint8_t u[16];
    assert(wm_principal(tenant, device, principal) == 105);
    assert(!wm_principal_device(principal, tenant, u));
    assert(!memcmp(u, m.device, 16));
    wm_uuid_format(u, id);
    assert(!strcmp(device, id));
    assert(wm_principal_device(principal, device, u));
    int n = wm_manifest_write(&m, text, sizeof text);
    assert(n > 0);
    struct wm_json d;
    assert(!wm_json_parse(&d, text, n));
    assert(!wm_manifest_parse(&d, 0, &parsed));
    assert(parsed.revision == UINT64_MAX && parsed.router_id == UINT64_MAX - 1
        && parsed.seqno == 65535);
    char* version = strstr(text, "\"version\":") + strlen("\"version\":");
    *version = '2';
    assert(wm_manifest_parse(&d, 0, &parsed));
    *version = '1';
    assert(wm_manifest_parse(&d, 0, &parsed));
    const char* bad[] = { "{\"a\":1,\"a\":2}", "{\"a\":01}", "{\"a\":1e3}", "{\"a\":1.5}",
        "{\"a\":1,}", "[1,]", "{\"\\u0061\":1}", "{\"a\":[1,2]", "true false" };
    for (unsigned i = 0; i < sizeof bad / sizeof *bad; i++)
        assert(wm_json_parse(&d, bad[i], strlen(bad[i])));
    assert(!wm_json_parse(&d, "18446744073709551616", 20));
    uint64_t value;
    assert(wm_json_u64(&d, 0, &value));
    const char nested[] = "{\"a\":[1,{\"b\":2}],\"c\":3}";
    assert(!wm_json_parse(&d, nested, sizeof nested - 1));
    assert(!wm_json_u64(&d, wm_json_member(&d, 0, "c"), &value) && value == 3);
    n = wm_hello_write(device, tenant, text, sizeof text);
    assert(n > 0);
    assert(!wm_hello_check(text, n, tenant, device));
    assert(wm_hello_check(text, n, device, tenant));
    version = strstr(text, "\"version\":") + strlen("\"version\":");
    *version = '2';
    assert(wm_hello_check(text, n, tenant, device));
    uint8_t babel[64];
    assert(wm_babel_announce(babel, m.device, m.router_id, m.seqno, 10) == 60);
    assert(wm_get16(babel + 2) == 56 && wm_get16(babel + 40) == 65535);
    uint8_t packet[1320] = { 0x60 }, first[1100], last[1100];
    wm_put16(packet + 4, 1280);
    packet[6] = 58;
    size_t a = wm_fragment(first, packet, sizeof packet, 7, 0),
           b = wm_fragment(last, packet, sizeof packet, 7, 1091);
    assert(a == 1100 && b == 238);
    struct wm_assembler assembly = { 0 };
    assert(wm_assemble(&assembly, last, b, 100) == 0);
    assert(wm_assemble(&assembly, first, a, 101) == 1320);
    assert(!memcmp(packet, assembly.packet, 1320));
    assert(wm_assemble(&assembly, first, a, 102) == 0);
    assert(wm_assemble(&assembly, first, a, 103) < 0);
    assert(wm_assemble(&assembly, first, a, 104) == 0);
    assert(wm_assemble(&assembly, last, b, 2000105) == 0);
    wm_put16(last + 7, 100);
    assert(wm_assemble(&assembly, last, b, 2000106) < 0);
    puts("mesh protocol bounds, exact integers, identity, hello, Babel and fragments passed");
    return 0;
}
