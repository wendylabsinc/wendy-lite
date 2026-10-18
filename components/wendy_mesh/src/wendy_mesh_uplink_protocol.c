#include "wendy_mesh_uplink.h"
#include <string.h>

bool wm_uplink_lease(const uint8_t response[3], uint8_t address[4])
{
    if (!response || !address || !wm_get16(response) || wm_get16(response) == 65535
        || response[2] > 1) return false;
    address[0] = 10;
    address[1] = 88;
    address[2] = response[0];
    address[3] = response[1];
    return true;
}
bool wm_uplink_ip4(const uint8_t* p, size_t n)
{
    if (!p || n < 20 || n > 1280 || p[0] != 0x45 || wm_get16(p + 2) != n
        || (wm_get16(p + 6) & 0xbfff) || (p[9] != 6 && p[9] != 17 && p[9] != 1))
        return false;
    uint32_t sum = 0;
    for (unsigned i = 0; i < 20; i += 2) sum += wm_get16(p + i);
    while (sum >> 16) sum = (sum & 65535) + (sum >> 16);
    return sum == 65535;
}
size_t wm_uplink_wrap(uint8_t out[WENDY_MESH_MTU], const uint8_t source[16],
    const uint8_t gateway[16], const uint8_t lease[4], const uint8_t* packet, size_t size)
{
    if (!out || !source || !gateway || !lease || !wm_uplink_ip4(packet, size)
        || memcmp(packet + 12, lease, 4)) return 0;
    memset(out, 0, 40);
    out[0] = 0x60;
    wm_put16(out + 4, size);
    out[6] = 4;
    out[7] = 64;
    memcpy(out + 8, source, 16);
    memcpy(out + 24, gateway, 16);
    memmove(out + 40, packet, size);
    return size + 40;
}
bool wm_uplink_unwrap(const uint8_t source[16], const uint8_t gateway[16],
    const uint8_t lease[4], const uint8_t* packet, size_t size)
{
    return source && gateway && lease && wm_ip_valid(packet, size) && packet[6] == 4
        && !memcmp(packet + 8, gateway, 16) && !memcmp(packet + 24, source, 16)
        && wm_uplink_ip4(packet + 40, size - 40) && !memcmp(packet + 56, lease, 4);
}
