#include "diagnostics.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "esp_heap_caps.h"
#include "esp_core_dump.h"
#include "esp_app_desc.h"
#include "esp_ota_ops.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "tinyusb.h"
#include "tinyusb_default_config.h"
#include "tinyusb_cdc_acm.h"

static _Atomic(const char *) boot_stage = "app entry";
static atomic_int stage_error;
static char previous_panic[192];
static char previous_location[96];

void mosaico_diagnostics_stage(const char *stage, esp_err_t error)
{
    atomic_store(&stage_error, error);
    atomic_store(&boot_stage, stage);
}

static void diagnostics_task(void *arg)
{
    (void)arg;
    char image_sha[65];
    esp_app_get_elf_sha256(image_sha, sizeof image_sha);
    const esp_partition_t *running = esp_ota_get_running_partition();
    for (;;) {
        /* Repeat so a host opened after boot can still locate a stalled startup.
         * A disconnected host must never block application initialization. */
        if (tud_cdc_n_connected(TINYUSB_CDC_ACM_1)) {
            if (previous_panic[0] || previous_location[0]) {
                tinyusb_cdcacm_write_queue(TINYUSB_CDC_ACM_1,
                    (const uint8_t *)previous_panic, strlen(previous_panic));
                tinyusb_cdcacm_write_queue(TINYUSB_CDC_ACM_1,
                    (const uint8_t *)previous_location, strlen(previous_location));
            }
            char text[256];
            int n = snprintf(text, sizeof text,
                "Mosaico uptime=%llds reset=%d stage=%s error=%s internal=%u dma_largest=%u PSRAM=%u image=%.16s slot=%s\r\n",
                (long long)(esp_timer_get_time() / 1000000), esp_reset_reason(),
                atomic_load(&boot_stage), esp_err_to_name(atomic_load(&stage_error)),
                (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),
                (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_DMA),
                (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM),
                image_sha, running ? running->label : "unknown");
            if (n > 0 && (size_t)n < sizeof text) {
                tinyusb_cdcacm_write_queue(TINYUSB_CDC_ACM_1, (const uint8_t *)text, n);
                tinyusb_cdcacm_write_flush(TINYUSB_CDC_ACM_1, 0);
            }
        }
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

void mosaico_diagnostics_start(void)
{
    if (esp_reset_reason() == ESP_RST_PANIC && esp_core_dump_image_check() == ESP_OK) {
        char reason[128];
        if (esp_core_dump_get_panic_reason(reason, sizeof reason) == ESP_OK) {
            snprintf(previous_panic, sizeof previous_panic, "Previous panic: %s\r\n", reason);
        }
        esp_core_dump_summary_t *summary = calloc(1, sizeof(*summary));
        if (summary && esp_core_dump_get_summary(summary) == ESP_OK) {
            snprintf(previous_location, sizeof previous_location,
                "Previous crash task=%s PC=0x%08lx\r\n",
                summary->exc_task, (unsigned long)summary->exc_pc);
        }
        free(summary);
    }
    const tinyusb_config_t config = TINYUSB_DEFAULT_CONFIG();
    esp_err_t error = tinyusb_driver_install(&config);
    if (error != ESP_OK) return;
    const tinyusb_config_cdcacm_t management = {.cdc_port = TINYUSB_CDC_ACM_0};
    if (tinyusb_cdcacm_init(&management) != ESP_OK) return;
    const tinyusb_config_cdcacm_t cdc = {.cdc_port = TINYUSB_CDC_ACM_1};
    error = tinyusb_cdcacm_init(&cdc);
    if (error != ESP_OK) return;
    xTaskCreate(diagnostics_task, "mosaico_usb", 3072, NULL, 2, NULL);
}
