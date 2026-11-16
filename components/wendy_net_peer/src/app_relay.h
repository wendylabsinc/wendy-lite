#pragma once
#ifdef ESP_PLATFORM
#include "sdkconfig.h"
#endif
#include "wendy_pki.h"
#ifndef CONFIG_WENDY_NET_TCP_RELAY_BUFFER_SIZE
#if ESP_PLATFORM && !CONFIG_SPIRAM
#define CONFIG_WENDY_NET_TCP_RELAY_BUFFER_SIZE 256
#else
#define CONFIG_WENDY_NET_TCP_RELAY_BUFFER_SIZE 1024
#endif
#endif
struct buffer {
    uint8_t data[CONFIG_WENDY_NET_TCP_RELAY_BUFFER_SIZE];
    size_t size, offset;
    bool eof;
};
/* Root actor pumps the buffered TLS BIO separately. Completion requires both
 * plaintext halves closed and final ciphertext drained by that owner. */
int wn_app_relay_step(wendy_pki_connection *, int, struct buffer[2], bool *, bool *, bool);
