#ifndef WENDY_PEER_IDENTITY_H
#define WENDY_PEER_IDENTITY_H
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

static const char wendy_identity_prefix[] = "spiffe://wendy.sh/tenant/";

// Parse a length-delimited SAN URI. Never treat certificate data as a C string.
static inline bool wendy_peer_identity(const unsigned char *uri, size_t size,
                                      const char *kind, unsigned char tenant[36])
{
    size_t prefix_len = sizeof(wendy_identity_prefix) - 1;
    if (size < prefix_len || memcmp(uri, wendy_identity_prefix, prefix_len) != 0) return false;
    size_t kind_len = strlen(kind);
    size_t name_start = prefix_len + 36 + 1 + kind_len + 1;
    if (size <= name_start || uri[prefix_len + 36] != '/' ||
        memcmp(uri + prefix_len + 37, kind, kind_len) != 0 ||
        uri[name_start - 1] != '/') return false;
    const unsigned char *uuid = uri + prefix_len;
    for (size_t i = 0; i < 36; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (uuid[i] != '-') return false;
        } else if (!((uuid[i] >= '0' && uuid[i] <= '9') ||
                    (uuid[i] >= 'a' && uuid[i] <= 'f'))) return false;
    }
    for (size_t i = name_start; i < size; i++) {
        unsigned char c = uri[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '@')) return false;
    }
    memcpy(tenant, uuid, 36);
    return true;
}
#endif
