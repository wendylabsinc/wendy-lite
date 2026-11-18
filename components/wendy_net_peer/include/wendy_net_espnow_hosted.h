#pragma once

/* ESP-Hosted custom message protocol. Requests and events carry the version
 * byte first. Frame events contain both station addresses as reported by RX. */
#define WN_ESPNOW_HOSTED_MESSAGE 0x574e4501u
#define WN_ESPNOW_HOSTED_VERSION 1
#define WN_ESPNOW_HOSTED_PAYLOAD 1285

enum wn_espnow_hosted_message {
    WNE_PROBE = 1, WNE_START, WNE_STOP, WNE_SEND,
    WNE_CAPABILITY, WNE_STARTED, WNE_RECEIVED, WNE_SENT
};
