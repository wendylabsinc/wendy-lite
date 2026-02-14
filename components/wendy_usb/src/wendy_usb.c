#include "wendy_usb.h"

#include <string.h>
#include <stdlib.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include "esp_log.h"
#include "esp_system.h"
#include "esp_rom_crc.h"
#include "tinyusb.h"
#include "tusb_cdc_acm.h"

static const char *TAG = "wendy_usb";

/* ── State ──────────────────────────────────────────────────────────── */

static wendy_usb_callbacks_t s_callbacks;
static TaskHandle_t s_rx_task;
static SemaphoreHandle_t s_tx_mutex;

/* Upload state machine */
static uint8_t *s_upload_buf = NULL;
static uint32_t s_upload_total = 0;
static uint32_t s_upload_received = 0;
static uint32_t s_upload_crc = 0;
static uint8_t  s_upload_slot = 0;

/* ── CRC32 ──────────────────────────────────────────────────────────── */

static uint32_t wendy_crc32(const uint8_t *data, uint32_t len)
{
    return esp_rom_crc32_le(0, data, len);
}

/* ── Low-level send ─────────────────────────────────────────────────── */

static esp_err_t send_message(uint8_t type, uint8_t seq,
                               const void *payload, uint32_t payload_len)
{
    if (!s_tx_mutex) return ESP_ERR_INVALID_STATE;

    xSemaphoreTake(s_tx_mutex, portMAX_DELAY);

    wendy_usb_header_t hdr = {
        .magic  = WENDY_USB_MAGIC,
        .type   = type,
        .seq    = seq,
        .length = payload_len,
    };

    /* Compute CRC over header + payload */
    uint32_t crc = wendy_crc32((const uint8_t *)&hdr, sizeof(hdr));
    if (payload && payload_len > 0) {
        crc = esp_rom_crc32_le(crc, (const uint8_t *)payload, payload_len);
    }

    /* Send header */
    tinyusb_cdcacm_write_queue(TINYUSB_CDC_ACM_0,
                                (const uint8_t *)&hdr, sizeof(hdr));

    /* Send payload */
    if (payload && payload_len > 0) {
        tinyusb_cdcacm_write_queue(TINYUSB_CDC_ACM_0,
                                    (const uint8_t *)payload, payload_len);
    }

    /* Send CRC */
    tinyusb_cdcacm_write_queue(TINYUSB_CDC_ACM_0,
                                (const uint8_t *)&crc, sizeof(crc));

    tinyusb_cdcacm_write_flush(TINYUSB_CDC_ACM_0, pdMS_TO_TICKS(100));

    xSemaphoreGive(s_tx_mutex);
    return ESP_OK;
}

static void send_ack(uint8_t seq)
{
    send_message(WENDY_MSG_ACK, seq, NULL, 0);
}

static void send_nack(uint8_t seq, const char *reason)
{
    send_message(WENDY_MSG_NACK, seq, reason,
                 reason ? (uint32_t)strlen(reason) : 0);
}

/* ── Message handlers ───────────────────────────────────────────────── */

static void handle_ping(uint8_t seq, const uint8_t *payload, uint32_t len)
{
    wendy_usb_device_info_t info = {
        .protocol_version = CONFIG_WENDY_USB_PROTOCOL_VERSION,
        .fw_version_major = CONFIG_WENDY_FIRMWARE_VERSION_MAJOR,
        .fw_version_minor = CONFIG_WENDY_FIRMWARE_VERSION_MINOR,
        .fw_version_patch = CONFIG_WENDY_FIRMWARE_VERSION_PATCH,
        .board_type       = 4, /* ESP32-C6 */
        .capabilities     = 0x01, /* WASM mode */
        .flash_free       = 0x180000, /* 1.5 MB per slot */
        .sram_free        = (uint32_t)esp_get_free_heap_size(),
        .wasm_slot_active = 0,
        .has_wasm_loaded  = (s_upload_buf != NULL) ? 1 : 0,
    };

#if CONFIG_WENDY_HAL_GPIO && CONFIG_WENDY_HAL_I2C
    info.capabilities |= 0x08; /* has peripherals */
#endif

    ESP_LOGI(TAG, "PING received, sending DEVICE_INFO");
    send_message(WENDY_MSG_DEVICE_INFO, seq, &info, sizeof(info));
}

static void handle_upload_start(uint8_t seq, const uint8_t *payload, uint32_t len)
{
    if (len < sizeof(wendy_usb_upload_start_t)) {
        send_nack(seq, "payload too short");
        return;
    }

    const wendy_usb_upload_start_t *start = (const wendy_usb_upload_start_t *)payload;

    /* Clean up any previous upload */
    if (s_upload_buf) {
        free(s_upload_buf);
        s_upload_buf = NULL;
    }

    if (start->total_size == 0 || start->total_size > 0x180000) {
        send_nack(seq, "invalid size");
        return;
    }

    s_upload_buf = malloc(start->total_size);
    if (!s_upload_buf) {
        send_nack(seq, "out of memory");
        return;
    }

    s_upload_total    = start->total_size;
    s_upload_received = 0;
    s_upload_crc      = start->crc32;
    s_upload_slot     = start->slot;

    ESP_LOGI(TAG, "UPLOAD_START: %lu bytes, crc=0x%08lx, slot=%d",
             (unsigned long)s_upload_total,
             (unsigned long)s_upload_crc,
             s_upload_slot);
    send_ack(seq);
}

static void handle_upload_chunk(uint8_t seq, const uint8_t *payload, uint32_t len)
{
    if (!s_upload_buf) {
        send_nack(seq, "no upload in progress");
        return;
    }
    if (len < sizeof(wendy_usb_upload_chunk_t)) {
        send_nack(seq, "chunk too short");
        return;
    }

    const wendy_usb_upload_chunk_t *chunk = (const wendy_usb_upload_chunk_t *)payload;
    uint32_t data_len = len - sizeof(wendy_usb_upload_chunk_t);
    const uint8_t *data = payload + sizeof(wendy_usb_upload_chunk_t);

    if (chunk->offset + data_len > s_upload_total) {
        send_nack(seq, "chunk exceeds total size");
        return;
    }

    memcpy(s_upload_buf + chunk->offset, data, data_len);
    s_upload_received += data_len;

    send_ack(seq);
}

static void handle_upload_done(uint8_t seq, const uint8_t *payload, uint32_t len)
{
    if (!s_upload_buf || s_upload_received < s_upload_total) {
        send_nack(seq, "upload incomplete");
        return;
    }

    /* Verify CRC */
    uint32_t actual_crc = wendy_crc32(s_upload_buf, s_upload_total);
    if (actual_crc != s_upload_crc) {
        ESP_LOGE(TAG, "CRC mismatch: expected 0x%08lx, got 0x%08lx",
                 (unsigned long)s_upload_crc, (unsigned long)actual_crc);
        free(s_upload_buf);
        s_upload_buf = NULL;
        send_nack(seq, "CRC mismatch");
        return;
    }

    ESP_LOGI(TAG, "UPLOAD_DONE: %lu bytes verified", (unsigned long)s_upload_total);
    send_ack(seq);

    if (s_callbacks.on_upload_complete) {
        s_callbacks.on_upload_complete(s_upload_buf, s_upload_total, s_upload_slot);
    }

    /* Callback receives a borrowed pointer; we free after it returns */
    free(s_upload_buf);
    s_upload_buf = NULL;
    s_upload_total = 0;
    s_upload_received = 0;
}

static void handle_run(uint8_t seq)
{
    ESP_LOGI(TAG, "RUN command received");
    send_ack(seq);
    if (s_callbacks.on_run) {
        s_callbacks.on_run();
    }
}

static void handle_stop(uint8_t seq)
{
    ESP_LOGI(TAG, "STOP command received");
    send_ack(seq);
    if (s_callbacks.on_stop) {
        s_callbacks.on_stop();
    }
}

static void handle_reset(uint8_t seq)
{
    ESP_LOGI(TAG, "RESET command received");
    send_ack(seq);
    if (s_callbacks.on_reset) {
        s_callbacks.on_reset();
    }
}

/* ── Receive task ───────────────────────────────────────────────────── */

static void dispatch_message(const wendy_usb_header_t *hdr,
                              const uint8_t *payload, uint32_t payload_len)
{
    switch (hdr->type) {
    case WENDY_MSG_PING:
        handle_ping(hdr->seq, payload, payload_len);
        break;
    case WENDY_MSG_UPLOAD_START:
        handle_upload_start(hdr->seq, payload, payload_len);
        break;
    case WENDY_MSG_UPLOAD_CHUNK:
        handle_upload_chunk(hdr->seq, payload, payload_len);
        break;
    case WENDY_MSG_UPLOAD_DONE:
        handle_upload_done(hdr->seq, payload, payload_len);
        break;
    case WENDY_MSG_RUN:
        handle_run(hdr->seq);
        break;
    case WENDY_MSG_STOP:
        handle_stop(hdr->seq);
        break;
    case WENDY_MSG_RESET:
        handle_reset(hdr->seq);
        break;
    default:
        ESP_LOGW(TAG, "unknown message type 0x%02x", hdr->type);
        send_nack(hdr->seq, "unknown type");
        break;
    }
}

/**
 * Read exactly `len` bytes from USB CDC, blocking until available.
 */
static bool usb_read_exact(uint8_t *buf, uint32_t len)
{
    uint32_t received = 0;
    while (received < len) {
        size_t avail = 0;
        esp_err_t err = tinyusb_cdcacm_read(TINYUSB_CDC_ACM_0,
                                              buf + received,
                                              len - received,
                                              &avail);
        if (err == ESP_OK && avail > 0) {
            received += avail;
        } else {
            vTaskDelay(pdMS_TO_TICKS(1));
        }
    }
    return true;
}

static void rx_task(void *arg)
{
    ESP_LOGI(TAG, "USB RX task started");

    wendy_usb_header_t hdr;
    uint8_t *payload = NULL;

    for (;;) {
        /* Read header */
        if (!usb_read_exact((uint8_t *)&hdr, sizeof(hdr))) {
            continue;
        }

        /* Validate magic */
        if (hdr.magic != WENDY_USB_MAGIC) {
            /* Scan forward for sync */
            ESP_LOGD(TAG, "bad magic 0x%04x, resyncing", hdr.magic);
            continue;
        }

        /* Read payload */
        if (hdr.length > 0) {
            if (hdr.length > 0x200000) { /* 2 MB sanity limit */
                ESP_LOGE(TAG, "payload too large: %lu", (unsigned long)hdr.length);
                continue;
            }
            payload = malloc(hdr.length);
            if (!payload) {
                ESP_LOGE(TAG, "OOM for payload (%lu bytes)", (unsigned long)hdr.length);
                continue;
            }
            if (!usb_read_exact(payload, hdr.length)) {
                free(payload);
                payload = NULL;
                continue;
            }
        }

        /* Read and verify CRC */
        uint32_t wire_crc;
        usb_read_exact((uint8_t *)&wire_crc, sizeof(wire_crc));

        uint32_t calc_crc = wendy_crc32((const uint8_t *)&hdr, sizeof(hdr));
        if (payload && hdr.length > 0) {
            calc_crc = esp_rom_crc32_le(calc_crc, payload, hdr.length);
        }

        if (calc_crc != wire_crc) {
            ESP_LOGW(TAG, "CRC mismatch on msg type=0x%02x", hdr.type);
            free(payload);
            payload = NULL;
            continue;
        }

        dispatch_message(&hdr, payload, hdr.length);

        free(payload);
        payload = NULL;
    }
}

/* ── Public API ─────────────────────────────────────────────────────── */

esp_err_t wendy_usb_init(const wendy_usb_callbacks_t *callbacks)
{
    if (callbacks) {
        s_callbacks = *callbacks;
    }

    s_tx_mutex = xSemaphoreCreateMutex();
    if (!s_tx_mutex) {
        return ESP_ERR_NO_MEM;
    }

    /* Initialize TinyUSB CDC */
    const tinyusb_config_t tusb_cfg = {
        .device_descriptor = NULL, /* use default */
        .string_descriptor = NULL,
        .external_phy      = false,
    };
    esp_err_t err = tinyusb_driver_install(&tusb_cfg);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "tinyusb_driver_install failed: %s", esp_err_to_name(err));
        return err;
    }

    tinyusb_config_cdcacm_t cdc_cfg = {
        .usb_dev = TINYUSB_USBDEV_0,
        .cdc_port = TINYUSB_CDC_ACM_0,
        .rx_unread_buf_sz = 1024,
        .callback_rx = NULL, /* we poll in the rx_task */
    };
    err = tusb_cdc_acm_init(&cdc_cfg);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "tusb_cdc_acm_init failed: %s", esp_err_to_name(err));
        return err;
    }

    /* Start receive task */
    BaseType_t ret = xTaskCreatePinnedToCore(
        rx_task, "wendy_usb_rx", 4096, NULL, 5, &s_rx_task, tskNO_AFFINITY);
    if (ret != pdPASS) {
        return ESP_ERR_NO_MEM;
    }

    ESP_LOGI(TAG, "USB CDC protocol handler initialized (v%d)",
             CONFIG_WENDY_USB_PROTOCOL_VERSION);
    return ESP_OK;
}

esp_err_t wendy_usb_send_stdout(const char *data, uint32_t len)
{
    return send_message(WENDY_MSG_STDOUT, 0, data, len);
}

esp_err_t wendy_usb_send_mem_stats(uint32_t heap_total, uint32_t heap_used,
                                    uint32_t stack_peak)
{
    struct __attribute__((packed)) {
        uint32_t heap_total;
        uint32_t heap_used;
        uint32_t stack_peak;
    } stats = { heap_total, heap_used, stack_peak };
    return send_message(WENDY_MSG_MEM_STATS, 0, &stats, sizeof(stats));
}

void wendy_usb_deinit(void)
{
    if (s_rx_task) {
        vTaskDelete(s_rx_task);
        s_rx_task = NULL;
    }
    if (s_tx_mutex) {
        vSemaphoreDelete(s_tx_mutex);
        s_tx_mutex = NULL;
    }
    if (s_upload_buf) {
        free(s_upload_buf);
        s_upload_buf = NULL;
    }
}
