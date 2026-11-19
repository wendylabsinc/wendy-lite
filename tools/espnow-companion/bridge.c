#include "wendy_net_espnow_hosted.h"
#include "wendy_net_espnow_peers.h"
#include "wendy_net_espnow_sdio.h"

#include "esp_hosted_peer_data.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"

#include <stdatomic.h>
#include <string.h>

static QueueHandle_t events;
static TaskHandle_t event_task;
static struct wn_espnow_peers radio_peers;
static atomic_bool active, sending, sent;
static atomic_uint direct_session, sending_session, completed_session;
static const uint8_t broadcast[6] = {255, 255, 255, 255, 255, 255};

struct event {
    uint32_t session;
    uint16_t size;
    uint8_t bytes[WN_ESPNOW_HOSTED_PAYLOAD + 14];
};

static void receive(const esp_now_recv_info_t *info, const uint8_t *bytes, int size)
{
    if (!atomic_load(&active) || !info || !bytes || size < 5 || size > WN_ESPNOW_HOSTED_PAYLOAD ||
        memcmp(bytes, "WNE\1", 4))
        return;
    struct event event = {.session = atomic_load(&direct_session),
                          .size = (uint16_t)(size + 14)};
    event.bytes[0] = WN_ESPNOW_HOSTED_VERSION;
    event.bytes[1] = WNE_RECEIVED;
    memcpy(event.bytes + 2, info->src_addr, 6);
    memcpy(event.bytes + 8, info->des_addr, 6);
    memcpy(event.bytes + 14, bytes, (size_t)size);
    if (xQueueSend(events, &event, 0) == pdTRUE)
        xTaskNotifyGive(event_task);
}

static void signal_sent(uint32_t session)
{
    atomic_store(&completed_session, session);
    atomic_store(&sent, true);
    xTaskNotifyGive(event_task);
}

static void completed(const esp_now_send_info_t *info, esp_now_send_status_t status)
{
    (void)info;
    (void)status;
    if (atomic_exchange(&sending, false))
        signal_sent(atomic_load(&sending_session));
}

static void stop(void)
{
    if (atomic_exchange(&active, false))
        (void)esp_now_deinit();
    atomic_store(&sending, false);
    atomic_store(&sent, false);
    atomic_store(&direct_session, 0);
}

static esp_err_t start(uint8_t channel, uint32_t session)
{
    uint8_t primary;
    wifi_second_chan_t secondary;
    if (esp_wifi_get_channel(&primary, &secondary) != ESP_OK || primary != channel)
        return ESP_ERR_INVALID_STATE;
    if (atomic_load(&active)) {
        if (session == atomic_load(&direct_session))
            return ESP_OK;
        /* A rebooted P4 starts a fresh session. Retire any work queued
         * for the previous host before accepting its replacement. */
        stop();
    }
    esp_err_t err = esp_now_init();
    if (err != ESP_OK)
        return err;
    radio_peers.count = 0;
    if ((err = wn_espnow_add_peer(broadcast)) != ESP_OK ||
        (err = esp_now_register_recv_cb(receive)) != ESP_OK ||
        (err = esp_now_register_send_cb(completed)) != ESP_OK) {
        (void)esp_now_deinit();
        return err;
    }
    atomic_store(&direct_session, session);
    atomic_store(&active, true);
    return ESP_OK;
}

static void send_event(uint8_t operation, uint8_t status)
{
    const uint8_t bytes[] = {WN_ESPNOW_HOSTED_VERSION, operation, status};
    (void)esp_hosted_send_custom_data(WN_ESPNOW_HOSTED_MESSAGE, bytes, sizeof bytes);
}

static bool send_operation(uint8_t operation)
{
    return operation == WNE_SEND || operation == WNE_SEND_AT_RATE;
}

static void enqueue_request(const uint8_t *bytes, size_t size, uint32_t session)
{
    if (size < 2 || size > WN_ESPNOW_HOSTED_PAYLOAD + 9 ||
        bytes[0] != WN_ESPNOW_HOSTED_VERSION)
        return;
    if (session && (!send_operation(bytes[1]) || session != atomic_load(&direct_session)))
        return;
    if (!session && send_operation(bytes[1]) && atomic_load(&direct_session))
        return;
    struct event event = {.session = session, .size = (uint16_t)size};
    memcpy(event.bytes, bytes, size);
    if (xQueueSend(events, &event, 0) == pdTRUE)
        xTaskNotifyGive(event_task);
    else if (send_operation(bytes[1]))
        signal_sent(session);
}

static void host_request(uint32_t id, const uint8_t *bytes, size_t size, void *context)
{
    (void)id;
    (void)context;
    if (size >= 2 && bytes[1] != WNE_RECEIVED)
        enqueue_request(bytes, size, 0);
}

void wendy_espnow_sdio_receive(const uint8_t *bytes, size_t size)
{
    if (size < WNE_SDIO_SESSION_BYTES + 2 || size > WNE_SDIO_MAX_BYTES)
        return;
    uint32_t session = wn_espnow_sdio_session(bytes);
    if (session)
        enqueue_request(bytes + WNE_SDIO_SESSION_BYTES, size - WNE_SDIO_SESSION_BYTES, session);
}

static void send_data(uint32_t session, const uint8_t *bytes, size_t size)
{
    if (size > WNE_SDIO_MAX_BYTES - WNE_SDIO_SESSION_BYTES ||
        session != atomic_load(&direct_session))
        return;
    if (!session) {
        (void)esp_hosted_send_custom_data(WN_ESPNOW_HOSTED_MESSAGE, bytes, size);
        return;
    }
    uint8_t frame[WNE_SDIO_MAX_BYTES];
    wn_espnow_sdio_put_session(frame, session);
    memcpy(frame + WNE_SDIO_SESSION_BYTES, bytes, size);
    (void)wendy_espnow_sdio_send(frame, size + WNE_SDIO_SESSION_BYTES);
}

static void send_result(uint32_t session, uint8_t status)
{
    const uint8_t result[] = {WN_ESPNOW_HOSTED_VERSION, WNE_SENT, status};
    send_data(session, result, sizeof result);
}

static void bridge_task(void *unused)
{
    (void)unused;
    struct event event;
    for (;;) {
        if (atomic_exchange(&sent, false))
            send_result(atomic_load(&completed_session), 0);
        if (xQueueReceive(events, &event, 0) != pdTRUE) {
            ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
            continue;
        }
        uint8_t *bytes = event.bytes;
        switch (bytes[1]) {
        case WNE_PROBE:
            send_event(WNE_CAPABILITY, WN_ESPNOW_HOSTED_RATE_CAPABILITY |
                                       WN_ESPNOW_HOSTED_SDIO_CAPABILITY);
            break;
        case WNE_START:
            if (event.size == 3)
                send_event(WNE_STARTED, start(bytes[2], 0) != ESP_OK);
            break;
        case WNE_START_SDIO:
            if (event.size == 3 + WNE_SDIO_SESSION_BYTES) {
                uint32_t session = wn_espnow_sdio_session(bytes + 3);
                uint8_t result[3 + WNE_SDIO_SESSION_BYTES] = {
                    WN_ESPNOW_HOSTED_VERSION, WNE_STARTED,
                    !session || start(bytes[2], session) != ESP_OK};
                wn_espnow_sdio_put_session(result + 3, session);
                (void)esp_hosted_send_custom_data(WN_ESPNOW_HOSTED_MESSAGE, result, sizeof result);
            }
            break;
        case WNE_STOP:
            stop();
            break;
        case WNE_SEND:
        case WNE_SEND_AT_RATE: {
            if (event.session != atomic_load(&direct_session))
                break;
            size_t header = bytes[1] == WNE_SEND_AT_RATE ? 9 : 8;
            if (event.size <= header || event.size > header + WN_ESPNOW_HOSTED_PAYLOAD ||
                !atomic_load(&active) || atomic_exchange(&sending, true)) {
                send_result(event.session, 1);
                break;
            }
            atomic_store(&sending_session, event.session);
            unsigned rate = header == 9 ? bytes[8] : 1;
            if (!wn_espnow_rate_valid(rate) ||
                wn_espnow_prepare_peer(&radio_peers, bytes + 2, rate) != ESP_OK ||
                esp_now_send(bytes + 2, bytes + header, event.size - header) != ESP_OK) {
                atomic_store(&sending, false);
                send_result(event.session, 1);
            }
            break;
        }
        case WNE_RECEIVED:
            if (event.size >= 19 && atomic_load(&active))
                send_data(event.session, bytes, event.size);
            break;
        }
    }
}

void wendy_espnow_bridge_init(void)
{
    events = xQueueCreate(4, sizeof(struct event));
    if (!events)
        return;
    if (xTaskCreate(bridge_task, "wendy_espnow", 6144, NULL, 4, &event_task) != pdPASS) {
        vQueueDelete(events);
        return;
    }
    ESP_ERROR_CHECK(esp_hosted_register_custom_callback(WN_ESPNOW_HOSTED_MESSAGE, host_request, NULL));
}
