#pragma once

#include "esp_now.h"
#include "esp_wifi.h"

#include <string.h>

/* ESP-NOW requires registrations for sending unencrypted frames. Only the
 * radio's send owner uses this cache, with no send in flight while it changes
 * registrations. Receive and authenticated TCP state do not depend on it. */
enum { WNE_UNICAST_CACHE_SIZE = 12 };

struct wn_espnow_peers {
    uint8_t recent[WNE_UNICAST_CACHE_SIZE][6];
    unsigned count;
};

static inline esp_err_t wn_espnow_add_peer(const uint8_t mac[6])
{
    esp_now_peer_info_t peer = {.ifidx = WIFI_IF_STA};
    memcpy(peer.peer_addr, mac, sizeof peer.peer_addr);
    return esp_now_add_peer(&peer);
}

static inline esp_err_t wn_espnow_prepare_peer(struct wn_espnow_peers *cache,
                                               const uint8_t mac[6])
{
    unsigned index = 0;
    while (index < cache->count && memcmp(cache->recent[index], mac, 6))
        index++;
    if (index == cache->count) {
        /* Broadcast and registrations owned by another caller stay outside
         * the cache and can never be evicted here. */
        if (esp_now_is_peer_exist(mac))
            return ESP_OK;
        if (mac[0] & 1)
            return ESP_ERR_INVALID_ARG;
        if (cache->count == WNE_UNICAST_CACHE_SIZE) {
            esp_err_t err = esp_now_del_peer(cache->recent[cache->count - 1]);
            if (err != ESP_OK && err != ESP_ERR_ESPNOW_NOT_FOUND)
                return err;
            index = --cache->count;
        }
        esp_err_t err = wn_espnow_add_peer(mac);
        if (err != ESP_OK)
            return err;
        cache->count++;
    }
    memmove(&cache->recent[1], cache->recent, index * sizeof cache->recent[0]);
    memcpy(cache->recent[0], mac, sizeof cache->recent[0]);
    return ESP_OK;
}
