#pragma once

#include "esp_now.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "wendy_net_espnow_hosted.h"

#include <string.h>

/* ESP-NOW requires registrations for sending unencrypted frames. Only the
 * radio's send owner uses this cache, with no send in flight while it changes
 * registrations. Receive and authenticated TCP state do not depend on it. */
enum { WNE_UNICAST_CACHE_SIZE = 12 };

struct wn_espnow_radio_peer {
    uint8_t mac[6];
    uint8_t requested_rate, rate;
};

struct wn_espnow_peers {
    struct wn_espnow_radio_peer recent[WNE_UNICAST_CACHE_SIZE];
    unsigned count;
};

static inline esp_err_t wn_espnow_add_peer(const uint8_t mac[6])
{
    esp_now_peer_info_t peer = {.ifidx = WIFI_IF_STA};
    memcpy(peer.peer_addr, mac, sizeof peer.peer_addr);
    return esp_now_add_peer(&peer);
}

static inline esp_err_t wn_espnow_apply_rate(const uint8_t mac[6], unsigned rate)
{
    esp_now_rate_config_t config = {.phymode = rate <= 2 ? WIFI_PHY_MODE_11B : WIFI_PHY_MODE_11G};
    switch (rate) {
    case 1: config.rate = WIFI_PHY_RATE_1M_L; break;
    case 2: config.rate = WIFI_PHY_RATE_2M_L; break;
    case 6: config.rate = WIFI_PHY_RATE_6M; break;
    case 12: config.rate = WIFI_PHY_RATE_12M; break;
    case 24: config.rate = WIFI_PHY_RATE_24M; break;
    default: return ESP_ERR_INVALID_ARG;
    }
    return esp_now_set_peer_rate_config(mac, &config);
}

static inline esp_err_t wn_espnow_prepare_peer(struct wn_espnow_peers *cache,
                                               const uint8_t mac[6], unsigned rate)
{
    unsigned index = 0;
    while (index < cache->count && memcmp(cache->recent[index].mac, mac, 6))
        index++;
    if (index == cache->count) {
        /* Broadcast and registrations owned by another caller stay outside
         * the cache and can never be evicted here. */
        if (esp_now_is_peer_exist(mac))
            return ESP_OK;
        if (mac[0] & 1)
            return ESP_ERR_INVALID_ARG;
        if (cache->count == WNE_UNICAST_CACHE_SIZE) {
            esp_err_t err = esp_now_del_peer(cache->recent[cache->count - 1].mac);
            if (err != ESP_OK && err != ESP_ERR_ESPNOW_NOT_FOUND)
                return err;
            index = --cache->count;
        }
        esp_err_t err = wn_espnow_add_peer(mac);
        if (err != ESP_OK)
            return err;
        struct wn_espnow_radio_peer *peer = &cache->recent[cache->count++];
        memcpy(peer->mac, mac, sizeof peer->mac);
        peer->requested_rate = peer->rate = 1;
    }
    struct wn_espnow_radio_peer peer = cache->recent[index];
    if (rate != peer.requested_rate) {
        esp_err_t err = wn_espnow_apply_rate(mac, rate);
        if (err == ESP_OK) {
            peer.rate = (uint8_t)rate;
            ESP_LOGI("wendy_espnow", "peer TX rate set to %u Mbit/s", rate);
        } else {
            ESP_LOGW("wendy_espnow", "peer TX rate %u Mbit/s unavailable: %s", rate,
                     esp_err_to_name(err));
            if (peer.rate != 1 && wn_espnow_apply_rate(mac, 1) != ESP_OK)
                return err;
            peer.rate = 1;
        }
        peer.requested_rate = (uint8_t)rate;
    }
    memmove(&cache->recent[1], cache->recent, index * sizeof cache->recent[0]);
    cache->recent[0] = peer;
    return ESP_OK;
}
