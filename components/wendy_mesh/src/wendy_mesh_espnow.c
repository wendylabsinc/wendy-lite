#include "esp_heap_caps.h"
#include "esp_now.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "wendy_mesh_datagram.h"
#include "wendy_mesh_radio.h"
#include "wendy_wifi.h"
#include <stdio.h>
#include <string.h>
struct frame {
    uint16_t size;
    uint8_t data[WM_DG_MAX];
};
static QueueHandle_t inbox;
static uint8_t peer[6];
static struct wm_datagram* link;
static bool initialized;
/* Wi-Fi callbacks only copy into a fixed, bounded queue. The mesh worker owns
 * retransmission, buffers and TLS. Overflow is repaired by retransmission. */
static void receive(const esp_now_recv_info_t* info, const uint8_t* data, int size)
{
    if (!info || !inbox || size < WM_DG_HEADER || size > WM_DG_MAX
        || memcmp(info->src_addr, peer, 6))
        return;
    struct frame frame = { .size = size };
    memcpy(frame.data, data, size);
    (void)xQueueSend(inbox, &frame, 0);
}
static int send_frame(void* ctx, const uint8_t* bytes, size_t size)
{
    (void)ctx;
    return esp_now_send(peer, bytes, size) == ESP_OK ? 0 : -1;
}
static int pump(void)
{
    struct frame frame;
    /* Bounded work also under malicious traffic. */
    for (unsigned i = 0; i < 16 && xQueueReceive(inbox, &frame, 0) == pdTRUE; ++i)
        wm_datagram_receive(link, frame.data, frame.size, send_frame, NULL);
    return wm_datagram_tick(link, esp_timer_get_time(), send_frame, NULL);
}
static ssize_t read_stream(void* ctx, void* buf, size_t n)
{
    (void)ctx;
    return pump() ? -1 : wm_datagram_read(link, buf, n);
}
static ssize_t write_stream(void* ctx, const void* buf, size_t n)
{
    (void)ctx;
    if (pump())
        return -1;
    int result = wm_datagram_write(link, buf, n, esp_timer_get_time());
    if (pump())
        return -1;
    return result;
}
static int wait_stream(void* ctx, bool writing, int64_t deadline)
{
    (void)ctx;
    do {
        if (pump())
            return -1;
        if (writing ? link->connected && !link->tx_size : link->size != 0)
            return 0;
        vTaskDelay(1);
    } while (esp_timer_get_time() < deadline);
    return 0;
}
static void close_stream(void) { link->failed = true; }
int wm_espnow_open(struct wm_carrier* carrier)
{
    if (!initialized) {
        unsigned a[6];
        int consumed = 0;
        const char* mac = CONFIG_WENDY_MESH_ESPNOW_PEER;
        if (sscanf(mac, "%2x:%2x:%2x:%2x:%2x:%2x%n", &a[0], &a[1], &a[2],
                &a[3], &a[4], &a[5], &consumed)
                != 6
            || consumed != 17 || mac[17])
            return -1;
        for (unsigned i = 0; i < 6; ++i)
            peer[i] = a[i];
        if ((peer[0] & 1) || !memcmp(peer, "\0\0\0\0\0\0", 6))
            return -1;
        if (wendy_wifi_mesh_radio_start(CONFIG_WENDY_MESH_ESPNOW_CHANNEL) != ESP_OK)
            return -1;
        inbox = xQueueCreate(16, sizeof(struct frame));
        if (!inbox)
            return -1;
        if (esp_now_init() != ESP_OK) {
            vQueueDelete(inbox);
            inbox = NULL;
            return -1;
        }
        esp_now_peer_info_t info = { .channel = CONFIG_WENDY_MESH_ESPNOW_CHANNEL,
            .ifidx = WIFI_IF_STA };
        memcpy(info.peer_addr, peer, 6);
        if (esp_now_add_peer(&info) != ESP_OK || esp_now_register_recv_cb(receive) != ESP_OK) {
            esp_now_deinit();
            vQueueDelete(inbox);
            inbox = NULL;
            return -1;
        }
        initialized = true;
    }
    if (!link) {
        if (heap_caps_get_free_size(MALLOC_CAP_SPIRAM) < sizeof *link + 512 * 1024)
            return -1;
        link = heap_caps_calloc(1, sizeof *link, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    }
    if (!link)
        return -1;
    xQueueReset(inbox);
    uint64_t epoch;
    do {
        esp_fill_random(&epoch, sizeof epoch);
    } while (!epoch);
    wm_datagram_init(link, epoch);
    int64_t deadline = esp_timer_get_time() + INT64_C(5000000);
    while (!link->connected) {
        if (pump() || esp_timer_get_time() >= deadline)
            return -1;
        vTaskDelay(1);
    }
    *carrier = (struct wm_carrier) {
        .stream = { .read = read_stream, .write = write_stream, .wait = wait_stream },
        .close = close_stream,
        .name = "ESP-NOW",
#if CONFIG_WENDY_MESH_ESPNOW_SERVER
        .server = true,
#endif
    };
    return 0;
}
