#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define WN_NAN_PRESENCE_SIZE 46
struct wn_nan_hint {
    uint8_t device[16];
    bool tls_only;
};
/* Discovery metadata only. Full TLS identity and signed routing admission
 * remain independent. UUIDs and the eight-byte mesh hash use network order. */
int wn_nan_presence_write(const uint8_t tenant[16],const uint8_t device[16],
    const uint8_t mesh[8],bool tls_only,uint8_t out[WN_NAN_PRESENCE_SIZE]);
bool wn_nan_presence_read(const uint8_t tenant[16],const uint8_t mesh[8],
    const void *bytes,size_t size,struct wn_nan_hint *out);
