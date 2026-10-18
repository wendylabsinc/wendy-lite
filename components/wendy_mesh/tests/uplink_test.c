#include "wendy_mesh_uplink.h"
#include <assert.h>
#include <string.h>

static void checksum(uint8_t* p)
{
    p[10] = p[11] = 0;
    unsigned sum = 0;
    for (unsigned i = 0; i < 20; i += 2) sum += wm_get16(p + i);
    while (sum >> 16) sum = (sum & 65535) + (sum >> 16);
    wm_put16(p + 10, ~sum);
}
int main(void)
{
    uint8_t lease[4], response[3] = { 1, 2, 0 };
    assert(wm_uplink_lease(response, lease));
    assert(!memcmp(lease, (uint8_t[]){10, 88, 1, 2}, 4));
    assert(!wm_uplink_lease((uint8_t[]){0, 0, 0}, lease));
    assert(!wm_uplink_lease((uint8_t[]){255, 255, 0}, lease));
    assert(!wm_uplink_lease((uint8_t[]){1, 2, 2}, lease));
    assert(wm_uplink_lease((uint8_t[]){1, 2, 1}, lease));
    uint8_t own[16] = {0xfd, 1}, gateway[16] = {0xfd, 2};
    uint8_t inner[1281] = {0x45}, outer[WENDY_MESH_MTU];
    inner[8] = 64; inner[9] = 6;
    memcpy(inner + 12, lease, 4);
    memcpy(inner + 16, (uint8_t[]){203, 0, 113, 5}, 4);
    wm_put16(inner + 2, 1280); checksum(inner);
    assert(wm_uplink_wrap(outer, own, gateway, lease, inner, 1280) == 1320);
    assert(!wm_uplink_unwrap(own, gateway, lease, outer, 1320));
    memcpy(inner + 12, (uint8_t[]){203, 0, 113, 5}, 4);
    memcpy(inner + 16, lease, 4); checksum(inner);
    memcpy(outer + 8, gateway, 16); memcpy(outer + 24, own, 16);
    memcpy(outer + 40, inner, 1280);
    assert(wm_uplink_unwrap(own, gateway, lease, outer, 1320));
    assert(!wm_uplink_unwrap(own, own, lease, outer, 1320));
    assert(!wm_uplink_unwrap(own, gateway, (uint8_t[]){10,88,1,3}, outer, 1320));
    for (size_t n = 0; n < 1280; n++) assert(!wm_uplink_ip4(inner, n));
    wm_put16(inner + 2, 1281); checksum(inner);
    assert(!wm_uplink_ip4(inner, 1281));
    wm_put16(inner + 2, 1280);
    for (unsigned flag = 1; flag <= 0x8000; flag <<= 1) {
        wm_put16(inner + 6, flag); checksum(inner);
        assert(wm_uplink_ip4(inner, 1280) == (flag == 0x4000));
    }
    wm_put16(inner + 6, 0);
    for (unsigned protocol = 0; protocol < 256; protocol++) {
        inner[9] = protocol; checksum(inner);
        assert(wm_uplink_ip4(inner, 1280) == (protocol == 1 || protocol == 6 || protocol == 17));
    }
    inner[9] = 17; checksum(inner); inner[10] ^= 1;
    assert(!wm_uplink_ip4(inner, 1280));
    inner[0] = 0x46; checksum(inner);
    assert(!wm_uplink_ip4(inner, 1280));
}
