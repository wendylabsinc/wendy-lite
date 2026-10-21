#include "wendy_mesh_discovery.h"
#include "wendy_mesh_protocol.h"
#include <stdio.h>
#include <string.h>

int wm_discovery_candidate(const char *tenant, const char *self,
    const char *principal, const uint8_t ip[4], struct wm_discovered_peer *out)
{
    uint8_t device[16], local[16];
    if (!out || !ip || !tenant || !self || wm_uuid_parse(self, local) ||
        wm_principal_device(principal, tenant, device) || !memcmp(device, local, 16) ||
        !ip[0] || ip[0] == 127 || ip[0] >= 224 || (ip[0] == 169 && ip[1] == 254))
        return -1;
    snprintf(out->host, sizeof out->host, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
    wm_uuid_format(device, out->device);
    return 0;
}
