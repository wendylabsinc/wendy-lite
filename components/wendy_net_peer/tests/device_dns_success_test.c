#include "wendy_net_peer_protocol.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    const char *names[] = {"device-7cd512eb-eb0c-4f68-b752-148e804e3d11.wendy.internal",
                           "DEVICE-7CD512EB-EB0C-4F68-B752-148E804E3D11.WENDY.INTERNAL.",
                           "device-7cd512eb-eb0c-4f68-b752-148e804e3d11.mesh.wendy.internal",
                           "device-7cd512eb-eb0c-4f68-b752-148e804e3d11.mesh.local.",
                           "DEVICE-7CD512EB-EB0C-4F68-B752-148E804E3D11.MESH.LOCAL"};
    const uint8_t expected[] = {0xfd, 0x45, 0xb8, 0x91, 0x56, 0x7f, 0x4f, 0x68,
                                0xb7, 0x52, 0x14, 0x8e, 0x80, 0x4e, 0x3d, 0x11};
    for (unsigned i = 0; i < sizeof names / sizeof names[0]; i++) {
        uint8_t device[16], address[16];
        assert(wn_device_hostname_parse(names[i], device) == 1);
        wn_address(device, address);
        assert(!memcmp(address, expected, 16));
    }
    const char *ordinary[] = {
        "jetson.wendy.internal", "jetson--a.wendy.internal", "device-reader.wendy.internal",
        "device-7cd512eb-eb0c-4f68-b752-148e804e3d11.wendy.internal.example",
        "device-7cd512eb-eb0c-4f68-b752-148e804e3d11.other.wendy.internal",
        "device-7cd512eb-eb0c-4f68-b752-148e804e3d11wendy.internal",
        "device-7cd512eb-eb0c-4f68-b752-148e804e3d1.wendy.internal",
        "device-7cd512eb-eb0c-4f68-b752-148e804e3d111.wendy.internal",
        "device-7cd512eb-eb0c-4f68-b752-148e804e3d11.wendy.internal..",
    };
    for (unsigned i = 0; i < sizeof ordinary / sizeof ordinary[0]; i++) {
        uint8_t device[16];
        assert(wn_device_hostname_parse(ordinary[i], device) == 0);
    }
    const char *malformed[] = {
        "device-7cd512eb-eb0c-4f68-b752-148e804e3d1z.wendy.internal",
        "device-7cd512eb_eb0c-4f68-b752-148e804e3d11.wendy.internal",
        "device-7cd512eb-eb0c-4f68-b752-148e804e3d1z.mesh.wendy.internal",
        "device-7cd512eb-eb0c-4f68-b752-148e804e3d1z.mesh.local",
    };
    for (unsigned i = 0; i < sizeof malformed / sizeof malformed[0]; i++) {
        uint8_t device[16];
        assert(wn_device_hostname_parse(malformed[i], device) == -1);
    }
    uint8_t device[16];
    assert(wn_device_hostname_parse(NULL, device) == 0);
    assert(wn_device_hostname_parse(names[0], NULL) == 0);
    puts("Canonical and legacy device names resolve without consuming ordinary DNS names");
    return 0;
}
