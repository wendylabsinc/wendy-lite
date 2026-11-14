/* SPDX-License-Identifier: Apache-2.0 */
#include "wendy_espnow.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

static struct {
    _Atomic(esp_now_recv_cb_t) cb; /* Published last, withdrawn first. */
    uint8_t prefix[WENDY_ESPNOW_PREFIX_MAX], size;
} users[WENDY_ESPNOW_USERS];
static atomic_uint dispatching;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static bool started;

/* Wi-Fi task. A few byte comparisons, then the user's own callback. */
static void dispatch(const esp_now_recv_info_t *info, const uint8_t *data, int len)
{
    atomic_fetch_add(&dispatching, 1);
    for (unsigned i = 0; i < WENDY_ESPNOW_USERS; i++) {
        esp_now_recv_cb_t cb = atomic_load(&users[i].cb);
        if (cb && len >= users[i].size && !memcmp(data, users[i].prefix, users[i].size))
            cb(info, data, len);
    }
    atomic_fetch_sub(&dispatching, 1);
}
static void withdraw(unsigned i)
{
    atomic_store(&users[i].cb, NULL);
    while (atomic_load(&dispatching))
        vTaskDelay(1);
}
esp_err_t wendy_espnow_subscribe(const void *prefix, size_t size, esp_now_recv_cb_t cb)
{
    if (!prefix || !size || size > WENDY_ESPNOW_PREFIX_MAX || !cb)
        return ESP_ERR_INVALID_ARG;
    pthread_mutex_lock(&lock);
    int slot = -1;
    for (int i = WENDY_ESPNOW_USERS - 1; i >= 0; i--)
        if (atomic_load(&users[i].cb) == cb) {
            slot = i;
            break;
        } else if (!atomic_load(&users[i].cb))
            slot = i;
    esp_err_t result = slot < 0 ? ESP_ERR_NO_MEM : ESP_OK;
    if (result == ESP_OK && !started) {
        result = esp_now_init();
        if (result == ESP_OK && (result = esp_now_register_recv_cb(dispatch)) != ESP_OK)
            esp_now_deinit();
        started = result == ESP_OK;
    }
    if (result == ESP_OK) {
        esp_now_peer_info_t everyone = {.ifidx = WIFI_IF_STA};
        memset(everyone.peer_addr, 0xff, sizeof everyone.peer_addr);
        if (!esp_now_is_peer_exist(everyone.peer_addr))
            result = esp_now_add_peer(&everyone);
    }
    if (result == ESP_OK) {
        withdraw((unsigned)slot);
        memcpy(users[slot].prefix, prefix, size);
        users[slot].size = (uint8_t)size;
        atomic_store(&users[slot].cb, cb);
    }
    pthread_mutex_unlock(&lock);
    return result;
}
void wendy_espnow_unsubscribe(esp_now_recv_cb_t cb)
{
    bool any = false;
    pthread_mutex_lock(&lock);
    for (unsigned i = 0; cb && i < WENDY_ESPNOW_USERS; i++) {
        if (atomic_load(&users[i].cb) == cb)
            withdraw(i);
        any |= atomic_load(&users[i].cb) != NULL;
    }
    if (cb && !any && started) {
        esp_now_unregister_recv_cb();
        esp_now_deinit();
        started = false;
    }
    pthread_mutex_unlock(&lock);
}
