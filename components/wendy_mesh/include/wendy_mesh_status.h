#pragma once
#include "wendy_mesh_protocol.h"

enum wendy_mesh_phase {
    WENDY_MESH_DISABLED,
    WENDY_MESH_PEER_REQUIRED,
    WENDY_MESH_WAITING_ENROLLMENT,
    WENDY_MESH_WAITING_WIFI,
    WENDY_MESH_DISCOVERING,
    WENDY_MESH_CONNECTING,
    WENDY_MESH_QUARANTINE,
    WENDY_MESH_ONLINE,
    WENDY_MESH_RETRYING,
    WENDY_MESH_UNAVAILABLE,
};

struct wendy_mesh_member {
    char device[37];
    uint32_t lease_seconds;
};

/* A leaf's observed topology, not a map of unobserved links between routers.
 * Members have live, verified, unambiguous /128 claims. No keys/certificates
 * or pointers to mutable protocol state are exposed. */
struct wendy_mesh_snapshot {
    enum wendy_mesh_phase phase;
    char carrier[16], device[37], peer[37];
    bool peer_connected, ip_active;
    uint32_t quarantine_seconds;
    unsigned member_count;
    struct wendy_mesh_member members[WENDY_MESH_ORIGINS_MAX];
};

/* Thread-safe bounded copy; does not perform network I/O or wait on TLS. */
void wendy_mesh_get_snapshot(struct wendy_mesh_snapshot *snapshot);
