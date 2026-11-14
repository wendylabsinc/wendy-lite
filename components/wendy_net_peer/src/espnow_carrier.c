/* SPDX-License-Identifier: Apache-2.0 */
#include "espnow_carrier.h"
#include "wendy_espnow.h"
#include "wendy_net_alloc.h"
#include "wendy_net_peer_protocol.h"
#include "wendy_pki_crypto.h"
#include "wendy_pki_work.h"
#include "wendy_wifi.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

/* ponytail: fixed ring of whole frames, twice the default window. A burst
 * beyond it is dropped and retransmitted; grow it if the drop counter moves. */
#define RING 16
#define STREAMS (CONFIG_WENDY_NET_ESPNOW_LINKS + 4)
#define RADIO_US INT64_C(1000000)
static const char *TAG = "wendy_net_espnow";
static const uint8_t everyone[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
/* Guards the stream layer. Held for one nonblocking call at a time. */
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
struct received {
    uint8_t mac[6];
    uint16_t size;
    uint8_t bytes[WNES_FRAME_MAX];
};
static struct {
    struct wnes *streams;
    struct received *ring;
    atomic_uint head, tail, dropped; /* Wi-Fi task produces, the actor consumes. */
    void (*wake)(void);
    uint8_t peers[STREAMS][6]; /* Unicast radio peers this carrier added. */
    unsigned peer_count, reported;
    uint8_t tenant[16], device[16], mesh[8];
    char tenant_text[37], device_text[37];
    bool scoped;
    uint8_t flags; /* What this node currently advertises. */
    int64_t radio_at, advert_at;
    /* Radio effect: the actor sets the wish and lends; the worker answers. */
    atomic_bool up, done;
    bool lent, want_up, fixed, paused, sleep_saved;
    wifi_ps_type_t sleep;
    uint8_t channel; /* Last one logged. */
} s;

/* Wi-Fi task. Copy and return; the stream layer recovers anything dropped. */
static void on_frame(const esp_now_recv_info_t *info, const uint8_t *data, int len)
{
    unsigned head = atomic_load(&s.head);
    if (len < 6 || len > WNES_FRAME_MAX)
        return;
    if (head - atomic_load(&s.tail) >= RING) {
        atomic_fetch_add(&s.dropped, 1);
        return;
    }
    struct received *r = &s.ring[head % RING];
    memcpy(r->mac, info->src_addr, 6);
    r->size = (uint16_t)len;
    memcpy(r->bytes, data, (size_t)len);
    atomic_store(&s.head, head + 1);
    s.wake();
}
/* I/O worker. The same steps the ESP-NOW reference application uses: with a
 * fixed channel the station is paused so nothing can move the radio; ESP-NOW
 * reception needs the radio awake, so modem sleep is switched off. */
static void radio_effect(void *unused)
{
    (void)unused;
    wifi_ps_type_t sleep;
    if (s.want_up && wendy_wifi_radio_available()) {
        bool tuned = true;
        if (s.fixed) {
            uint8_t channel = 0;
            wifi_second_chan_t second;
            wifi_ap_record_t ap;
            if (!s.paused || esp_wifi_sta_get_ap_info(&ap) == ESP_OK ||
                esp_wifi_get_channel(&channel, &second) != ESP_OK ||
                channel != CONFIG_WENDY_NET_ESPNOW_CHANNEL) {
                (void)wendy_wifi_set_station_enabled(false);
                s.paused = true;
                (void)esp_wifi_start(); /* Otherwise only started to join a network. */
                tuned = esp_wifi_set_channel(CONFIG_WENDY_NET_ESPNOW_CHANNEL,
                                             WIFI_SECOND_CHAN_NONE) == ESP_OK;
            }
        }
        if (esp_wifi_get_ps(&sleep) == ESP_OK && sleep != WIFI_PS_NONE) {
            if (!s.sleep_saved) {
                s.sleep = sleep;
                s.sleep_saved = true;
            }
            (void)esp_wifi_set_ps(WIFI_PS_NONE);
        }
        if (tuned && !atomic_load(&s.up) &&
            wendy_espnow_subscribe(WNES_MAGIC, 4, on_frame) == ESP_OK)
            atomic_store(&s.up, true);
        uint8_t channel = 0;
        wifi_second_chan_t second;
        if (atomic_load(&s.up) && esp_wifi_get_channel(&channel, &second) == ESP_OK &&
            channel != s.channel) {
            s.channel = channel;
            /* Every board has to be on one channel. A board that stays on its
             * Wi-Fi network follows that network's channel instead. */
            if (channel == CONFIG_WENDY_NET_ESPNOW_CHANNEL)
                ESP_LOGI(TAG, "ESP-NOW carrier on channel %u", channel);
            else
                ESP_LOGW(TAG, "ESP-NOW carrier on channel %u, not the configured %u: boards on "
                              "the configured channel cannot hear this one",
                         channel, CONFIG_WENDY_NET_ESPNOW_CHANNEL);
        }
    } else if (!s.want_up) {
        if (atomic_exchange(&s.up, false)) {
            for (unsigned i = 0; i < s.peer_count; i++)
                (void)esp_now_del_peer(s.peers[i]);
            wendy_espnow_unsubscribe(on_frame);
        }
        s.peer_count = 0;
        if (s.sleep_saved)
            (void)esp_wifi_set_ps(s.sleep);
        if (s.paused)
            (void)wendy_wifi_set_station_enabled(true);
        s.sleep_saved = s.paused = false;
        s.channel = 0;
    }
    atomic_store(&s.done, true);
}
/* Radio peers no stream uses any more leave the 20-entry SDK table. */
static void prune_peers(void)
{
    for (unsigned i = 0; i < s.peer_count;)
        if (!wnes_uses(s.streams, s.peers[i])) {
            (void)esp_now_del_peer(s.peers[i]);
            memcpy(s.peers[i], s.peers[--s.peer_count], 6);
        } else
            i++;
}
static int radio_send(void *context, const uint8_t mac[6], const void *frame, size_t size)
{
    (void)context;
    if (!atomic_load(&s.up))
        return 0;
    if (!esp_now_is_peer_exist(mac)) {
        esp_now_peer_info_t peer = {.ifidx = WIFI_IF_STA};
        memcpy(peer.peer_addr, mac, 6);
        if (s.peer_count == STREAMS)
            prune_peers();
        if (s.peer_count == STREAMS || esp_now_add_peer(&peer) != ESP_OK)
            return 0; /* Counts as a lost frame; the timer retries. */
        memcpy(s.peers[s.peer_count++], mac, 6);
    }
    /* Only a full transmit queue is worth an early retry. */
    return esp_now_send(mac, frame, size) == ESP_ERR_ESPNOW_NO_MEM;
}
static ssize_t stream_read(void *conn, void *data, size_t size)
{
    pthread_mutex_lock(&lock);
    ssize_t n = wnes_read(conn, data, size);
    pthread_mutex_unlock(&lock);
    return n;
}
static ssize_t stream_write(void *conn, const void *data, size_t size)
{
    pthread_mutex_lock(&lock);
    ssize_t n = wnes_write(conn, data, size);
    pthread_mutex_unlock(&lock);
    return n;
}
/* Only blocking users call this (the signed-time exchange on the I/O worker).
 * A hint, like the BLE stream's: sleep one tick, the caller rechecks. */
static int stream_wait(void *conn, bool writing, int64_t deadline)
{
    (void)conn;
    (void)writing;
    (void)deadline;
    vTaskDelay(1);
    return 0;
}

bool wnen_start(void (*wake)(void))
{
    if (s.streams)
        return true;
    if (s.lent || !wake)
        return false; /* A previous stop is still returning the radio. */
    struct wnes_config k;
    wnes_defaults(&k);
    k.frame_bytes = CONFIG_WENDY_NET_ESPNOW_FRAME_BYTES;
    /* A handshake may sit silent while the serialized crypto worker is busy;
     * allow as long as the TLS setup budget. Routing hellos keep a live link
     * far inside this, and unanswered data fails within seconds regardless. */
    k.idle_us = 60000000;
    k.alloc = wendy_net_malloc;
    k.free = wendy_net_free;
    k.send = radio_send;
    k.random = esp_random;
    s.ring = wendy_net_malloc(RING * sizeof *s.ring);
    s.streams = s.ring ? wnes_open(&k, STREAMS) : NULL;
    if (!s.streams) {
        wendy_net_free(s.ring);
        s.ring = NULL;
        return false;
    }
    atomic_store(&s.head, 0);
    atomic_store(&s.tail, 0);
    s.wake = wake;
    s.scoped = false;
    s.radio_at = 0;
    /* Boards powered together must not all advertise in the same instant. */
    s.advert_at = esp_timer_get_time() + esp_random() % (CONFIG_WENDY_NET_ESPNOW_ADVERT_MS * 1000);
    return true;
}
bool wnen_stop(void)
{
    if (s.lent && !atomic_load(&s.done))
        return false;
    s.lent = false;
    if (s.streams) {
        pthread_mutex_lock(&lock);
        (void)wnes_tick(s.streams, esp_timer_get_time()); /* Closing notices, best effort. */
        wnes_close(s.streams);
        s.streams = NULL;
        pthread_mutex_unlock(&lock);
    }
    if (atomic_load(&s.up) || s.paused || s.sleep_saved) {
        s.want_up = false;
        atomic_store(&s.done, false);
        s.lent = wendy_pki_io_work_submit(radio_effect, NULL);
        return false;
    }
    wendy_net_free(s.ring); /* Unsubscribed: the Wi-Fi task no longer writes it. */
    s.ring = NULL;
    return true;
}
static void scope(const struct wnen_intent *intent)
{
    char canonical[37], network[64];
    uint8_t hash[32];
    if (s.scoped && !strcmp(s.tenant_text, intent->tenant) &&
        !strncmp(s.device_text, intent->device, sizeof s.device_text - 1))
        return;
    s.scoped = false;
    if (wn_uuid_parse(intent->tenant, s.tenant) || strlen(intent->device) < 36 ||
        strlen(intent->tenant) != 36)
        return;
    snprintf(s.tenant_text, sizeof s.tenant_text, "%s", intent->tenant);
    snprintf(s.device_text, sizeof s.device_text, "%s", intent->device);
    if (wn_uuid_parse(s.device_text, s.device))
        return;
    /* The same default mesh scope the LAN and BLE discovery hints use. */
    wn_uuid_format(s.tenant, canonical);
    int n = snprintf(network, sizeof network, "tenant:%s:default", canonical);
    if (wendy_pki_sha256((const uint8_t *)network, (size_t)n, hash))
        return;
    memcpy(s.mesh, hash, sizeof s.mesh);
    s.scoped = true;
}
bool wnen_poll(const struct wnen_intent *intent, wnen_seen seen, void *context)
{
    if (!s.streams)
        return false;
    int64_t now = esp_timer_get_time();
    bool progress = false;
    if (s.lent && atomic_load(&s.done))
        s.lent = false;
    if (!s.lent && now >= s.radio_at) {
        s.want_up = true;
        s.fixed = intent->fixed_channel;
        atomic_store(&s.done, false);
        s.lent = wendy_pki_io_work_submit(radio_effect, NULL);
        /* Brisk until the radio is up, then an occasional check that it stayed. */
        s.radio_at = now + (atomic_load(&s.up) ? 5 * RADIO_US : RADIO_US);
        pthread_mutex_lock(&lock);
        if (atomic_load(&s.up))
            prune_peers();
        pthread_mutex_unlock(&lock);
        unsigned dropped = atomic_load(&s.dropped);
        if (dropped != s.reported)
            ESP_LOGW(TAG, "receive ring overflowed: frames dropped=%u", dropped);
        s.reported = dropped;
    }
    scope(intent);
    pthread_mutex_lock(&lock);
    for (unsigned n = 0; n < RING; n++) {
        unsigned tail = atomic_load(&s.tail);
        if (tail == atomic_load(&s.head))
            break;
        const struct received *r = &s.ring[tail % RING];
        uint8_t device[16], flags;
        if (r->bytes[5] != WNES_ADVERT)
            wnes_input(s.streams, r->mac, r->bytes, r->size, now);
        else if (s.scoped && seen &&
                 wnes_advert_read(s.tenant, s.mesh, r->bytes, r->size, device, &flags) &&
                 memcmp(device, s.device, 16))
            seen(context, r->mac, device, flags);
        atomic_store(&s.tail, tail + 1);
        progress = true;
    }
    s.flags = !s.scoped || !atomic_load(&s.up) ? 0
                                               : (intent->accepting ? WNES_ACCEPTING : 0) |
                                                     (intent->time_relay ? WNES_TIME_RELAY : 0);
    wnes_accepting(s.streams, (uint8_t)((s.flags & WNES_ACCEPTING ? 1 << WNES_MESH : 0) |
                                        (s.flags & WNES_TIME_RELAY ? 1 << WNES_TIME : 0)));
    (void)wnes_tick(s.streams, now);
    pthread_mutex_unlock(&lock);
    if (s.flags && now >= s.advert_at) {
        uint8_t advert[WNES_ADVERT_SIZE];
        if (wnes_advert_write(s.tenant, s.device, s.mesh, s.flags, advert) > 0)
            (void)esp_now_send(everyone, advert, sizeof advert);
        /* Sparse and jittered: 75-125% of the interval, four times rarer
         * once this node has an ESP-NOW link. Newcomers advertise at the
         * base rate and are dialed by whoever hears them. */
        int64_t interval =
            INT64_C(1000) * CONFIG_WENDY_NET_ESPNOW_ADVERT_MS * (intent->linked ? 4 : 1);
        s.advert_at = now + interval * 3 / 4 + (int64_t)(esp_random() % (uint32_t)(interval / 2));
    }
    return progress;
}
int64_t wnen_deadline(void)
{
    if (!s.streams)
        return INT64_MAX;
    pthread_mutex_lock(&lock);
    int64_t next = wnes_tick(s.streams, esp_timer_get_time());
    pthread_mutex_unlock(&lock);
    if (s.radio_at < next)
        next = s.radio_at;
    if (s.flags && s.advert_at < next)
        next = s.advert_at;
    if (atomic_load(&s.tail) != atomic_load(&s.head))
        next = 0;
    return next;
}
struct wnes_conn *wnen_dial(const uint8_t mac[6], uint8_t service)
{
    if (!s.streams || !atomic_load(&s.up))
        return NULL;
    pthread_mutex_lock(&lock);
    struct wnes_conn *conn = wnes_connect(s.streams, mac, service, esp_timer_get_time());
    pthread_mutex_unlock(&lock);
    return conn;
}
struct wnes_conn *wnen_take(uint8_t mac[6], uint8_t *service)
{
    pthread_mutex_lock(&lock);
    struct wnes_conn *conn = wnes_accept(s.streams, mac, service);
    pthread_mutex_unlock(&lock);
    return conn;
}
struct wendy_pki_stream wnen_stream(struct wnes_conn *conn)
{
    return (struct wendy_pki_stream){
        .context = conn, .read = stream_read, .write = stream_write, .wait = stream_wait};
}
bool wnen_drained(struct wnes_conn *conn)
{
    pthread_mutex_lock(&lock);
    bool drained = wnes_drained(conn);
    pthread_mutex_unlock(&lock);
    return drained;
}
void wnen_release(struct wnes_conn *conn)
{
    pthread_mutex_lock(&lock);
    wnes_release(conn, esp_timer_get_time());
    pthread_mutex_unlock(&lock);
}
