#pragma once

#include "wendy_net_espnow_hosted.h"
#include <stddef.h>
#include <stdint.h>

/* Private interface in the four-bit Hosted SDIO envelope. It is used only
 * after the companion advertises support and echoes the START session. */
enum {
    WNE_SDIO_INTERFACE = 14,
    WNE_SDIO_SESSION_BYTES = 4,
    WNE_SDIO_MAX_BYTES = WNE_SDIO_SESSION_BYTES + 14 + WN_ESPNOW_HOSTED_PAYLOAD,
};

static inline void wn_espnow_sdio_put_session(uint8_t *bytes, uint32_t session)
{
    for (unsigned i = 0; i < WNE_SDIO_SESSION_BYTES; ++i)
        bytes[i] = (uint8_t)(session >> (8 * i));
}

static inline uint32_t wn_espnow_sdio_session(const uint8_t *bytes)
{
    uint32_t session = 0;
    for (unsigned i = 0; i < WNE_SDIO_SESSION_BYTES; ++i)
        session |= (uint32_t)bytes[i] << (8 * i);
    return session;
}

bool wendy_espnow_sdio_send(const uint8_t *bytes, size_t size);
void wendy_espnow_sdio_receive(const uint8_t *bytes, size_t size);
