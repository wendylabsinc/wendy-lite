#include "wendy_net_espnow_hosted.h"

#include "esp_hosted_peer_data.h"
#include "esp_now.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"

#include <stdatomic.h>
#include <string.h>

static QueueHandle_t events;
static atomic_bool active, sending, sent;
static const uint8_t broadcast[6] = {255, 255, 255, 255, 255, 255};

struct event {
    uint16_t size;
    uint8_t bytes[WN_ESPNOW_HOSTED_PAYLOAD + 14];
};

static esp_err_t register_peer(const uint8_t mac[6])
{
    if (esp_now_is_peer_exist(mac))
        return ESP_OK;
    esp_now_peer_info_t peer = {.ifidx = WIFI_IF_STA};
    memcpy(peer.peer_addr, mac, 6);
    esp_err_t err = esp_now_add_peer(&peer);
    if (err != ESP_ERR_ESPNOW_FULL)
        return err;
    esp_now_peer_info_t stale;
    if (esp_now_fetch_peer(true, &stale) != ESP_OK || esp_now_del_peer(stale.peer_addr) != ESP_OK)
        return err;
    return esp_now_add_peer(&peer);
}

static void receive(const esp_now_recv_info_t *info, const uint8_t *bytes, int size)
{
    if (!atomic_load(&active) || !info || size < 5 || size > WN_ESPNOW_HOSTED_PAYLOAD ||
        memcmp(bytes, "WNE\1", 4))
        return;
    struct event event = {.size = (uint16_t)(size + 14)};
    event.bytes[0] = WN_ESPNOW_HOSTED_VERSION;
    event.bytes[1] = WNE_RECEIVED;
    memcpy(event.bytes + 2, info->src_addr, 6);
    memcpy(event.bytes + 8, info->des_addr, 6);
    memcpy(event.bytes + 14, bytes, (size_t)size);
    (void)xQueueSend(events, &event, 0);
}

static void completed(const esp_now_send_info_t *info, esp_now_send_status_t status)
{
    (void)info;
    (void)status;
    atomic_store(&sending, false);
    atomic_store(&sent, true);
}

static esp_err_t start(uint8_t channel)
{
    uint8_t primary;
    wifi_second_chan_t secondary;
    if (esp_wifi_get_channel(&primary, &secondary) != ESP_OK || primary != channel)
        return ESP_ERR_INVALID_STATE;
    if (atomic_load(&active))
        return ESP_OK;
    esp_err_t err = esp_now_init();
    if (err != ESP_OK)
        return err;
    if ((err = register_peer(broadcast)) != ESP_OK ||
        (err = esp_now_register_recv_cb(receive)) != ESP_OK ||
        (err = esp_now_register_send_cb(completed)) != ESP_OK) {
        (void)esp_now_deinit();
        return err;
    }
    atomic_store(&active, true);
    return ESP_OK;
}

static void send_event(uint8_t operation, uint8_t status)
{
    const uint8_t bytes[] = {WN_ESPNOW_HOSTED_VERSION, operation, status};
    (void)esp_hosted_send_custom_data(WN_ESPNOW_HOSTED_MESSAGE, bytes, sizeof bytes);
}

static void host_request(uint32_t id, const uint8_t *bytes, size_t size, void *context)
{
    (void)id;
    (void)context;
    if (size < 2 || size > WN_ESPNOW_HOSTED_PAYLOAD + 8 ||
        bytes[0] != WN_ESPNOW_HOSTED_VERSION)
        return;
    struct event event = {.size = (uint16_t)size};
    memcpy(event.bytes, bytes, size);
    if (xQueueSend(events, &event, 0) != pdTRUE && bytes[1] == WNE_SEND)
        atomic_store(&sent, true);
}

static void bridge_task(void *unused)
{
    (void)unused;
    struct event event;
    for (;;) {
        if (atomic_exchange(&sent, false))
            send_event(WNE_SENT, 0);
        if (xQueueReceive(events, &event, pdMS_TO_TICKS(10)) != pdTRUE)
            continue;
        uint8_t *bytes = event.bytes;
        switch (bytes[1]) {
        case WNE_PROBE:
            send_event(WNE_CAPABILITY, 0);
            break;
        case WNE_START:
            if (event.size == 3)
                send_event(WNE_STARTED, start(bytes[2]) != ESP_OK);
            break;
        case WNE_STOP:
            if (atomic_exchange(&active, false))
                (void)esp_now_deinit();
            atomic_store(&sending, false);
            break;
        case WNE_SEND:
            if (event.size <= 8 || !atomic_load(&active) || atomic_exchange(&sending, true)) {
                send_event(WNE_SENT, 1);
                break;
            }
            if (register_peer(bytes + 2) != ESP_OK ||
                esp_now_send(bytes + 2, bytes + 8, event.size - 8) != ESP_OK) {
                atomic_store(&sending, false);
                send_event(WNE_SENT, 1);
            }
            break;
        case WNE_RECEIVED:
            if (event.size >= 19 && atomic_load(&active))
                (void)esp_hosted_send_custom_data(WN_ESPNOW_HOSTED_MESSAGE, bytes, event.size);
            break;
        }
    }
}

void wendy_espnow_bridge_init(void)
{
    events = xQueueCreate(4, sizeof(struct event));
    if (!events)
        return;
    if (xTaskCreate(bridge_task, "wendy_espnow", 4608, NULL, 4, NULL) != pdPASS) {
        vQueueDelete(events);
        return;
    }
    ESP_ERROR_CHECK(esp_hosted_register_custom_callback(WN_ESPNOW_HOSTED_MESSAGE, host_request, NULL));
}
