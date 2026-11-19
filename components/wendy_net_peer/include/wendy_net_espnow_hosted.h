#pragma once

#include <stdbool.h>

/* ESP-Hosted custom message protocol. Requests and events carry the version
 * byte first. Frame events contain both station addresses as reported by RX. */
#define WN_ESPNOW_HOSTED_MESSAGE 0x574e4501u
#define WN_ESPNOW_HOSTED_VERSION 1
#define WN_ESPNOW_HOSTED_PAYLOAD 1285
#define WN_ESPNOW_HOSTED_RATE_CAPABILITY 1u
#define WN_ESPNOW_HOSTED_SDIO_CAPABILITY 2u

enum wn_espnow_hosted_message {
    WNE_PROBE = 1, WNE_START, WNE_STOP, WNE_SEND,
    WNE_CAPABILITY, WNE_STARTED, WNE_RECEIVED, WNE_SENT, WNE_SEND_AT_RATE, WNE_START_SDIO
};

static inline bool wn_espnow_rate_valid(unsigned rate)
{
    return rate == 1 || rate == 2 || rate == 6 || rate == 12 || rate == 24;
}
