#include "wendy_mesh_directory.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void origin(struct wm_origin *o, const char *uuid, int64_t deadline)
{
    memset(o, 0, sizeof *o);
    assert(wm_uuid_parse(uuid, o->device) == 0);
    o->revision = 1;
    o->expires_us = deadline;
}

int main(void)
{
    const int64_t now = 1000000;
    struct wm_directory d = {0};
    const char *a = "11111111-1111-4111-8111-111111111111";
    const char *b = "22222222-2222-4222-8222-222222222222";
    const char *collision = "33333333-3333-4111-8111-111111111111";
    origin(&d.origins[0], a, now + 1000001);
    origin(&d.origins[1], b, now); /* Exact expiry is not live. */
    origin(&d.origins[2], "44444444-4444-4444-8444-444444444444", 0); /* Withdrawal. */
    origin(&d.origins[3], "55555555-5555-4555-8555-555555555555", now + 9000000);
    d.origins[3].revision = 0; /* Certificate alone is not a signed route. */
    d.count = 4;
    struct wm_directory original = d;
    struct wendy_mesh_member members[WENDY_MESH_ORIGINS_MAX];
    memset(members, 0xa5, sizeof members);
    assert(wm_directory_members(&d, now, members, WENDY_MESH_ORIGINS_MAX) == 1);
    assert(strcmp(members[0].device, a) == 0 && members[0].lease_seconds == 2);
    assert((unsigned char)members[1].device[0] == 0xa5);
    assert(memcmp(&original, &d, sizeof d) == 0); /* Rendering never mutates receipts. */
    assert(wm_directory_members(&d, now + 1000001, members, WENDY_MESH_ORIGINS_MAX) == 0);
    assert(wm_directory_members(&d, -1, members, WENDY_MESH_ORIGINS_MAX) == 0);
    assert(wm_directory_members(&d, now, members, 0) == 0);
    assert(wm_directory_members(NULL, now, members, 1) == 0);
    assert(wm_directory_members(&d, now, NULL, 1) == 0);

    origin(&d.origins[1], collision, now + 2000000);
    assert(wm_directory_members(&d, now, members, WENDY_MESH_ORIGINS_MAX) == 0);
    d.origins[1].expires_us = now; /* An expired collision no longer suppresses A. */
    assert(wm_directory_members(&d, now, members, WENDY_MESH_ORIGINS_MAX) == 1);

    d.count = WENDY_MESH_ORIGINS_MAX;
    for (unsigned i = 0; i < d.count; ++i) {
        origin(&d.origins[i], b, now + 5000000);
        d.origins[i].device[15] = i;
    }
    memset(members, 0xa5, sizeof members);
    assert(wm_directory_members(&d, now, members, 3) == 3);
    assert((unsigned char)members[3].device[0] == 0xa5);
    assert(wm_directory_members(&d, now, members, WENDY_MESH_ORIGINS_MAX) == WENDY_MESH_ORIGINS_MAX);
    puts("topology: expiry, withdrawal, unsigned origins, collisions, bounds and immutable receipts passed");
    return 0;
}
