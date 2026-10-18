#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_nn.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "wendy_benchmark.h"
#if CONFIG_WENDY_SENSOR_LINK_ESP32S31_KORVO_1
#include "wendy_sensor_link.h"
#endif

#if !CONFIG_NN_OPTIMIZED || CONFIG_NN_SKIP_NUDGE
#error "The Korvo benchmark requires optimized, bit-exact ESP-NN kernels"
#endif

static const char *TAG = "wendy_bench";

static void report_heap(void)
{
    const uint32_t internal = MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT;
    const uint32_t external = MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT;
    const uint32_t dma = MALLOC_CAP_INTERNAL | MALLOC_CAP_DMA;
    ESP_LOGI(TAG, "WENDY_BENCH {\"test\":\"heap\",\"time_us\":%" PRId64
             ",\"internal_free\":%zu,\"internal_min\":%zu,\"internal_largest\":%zu"
             ",\"dma_largest\":%zu,\"psram_free\":%zu,\"psram_largest\":%zu"
             ",\"benchmark_stack_free\":%u}",
             esp_timer_get_time(), heap_caps_get_free_size(internal),
             heap_caps_get_minimum_free_size(internal),
             heap_caps_get_largest_free_block(internal),
             heap_caps_get_largest_free_block(dma),
             heap_caps_get_free_size(external), heap_caps_get_largest_free_block(external),
             (unsigned)uxTaskGetStackHighWaterMark(NULL));
#if CONFIG_WENDY_SENSOR_LINK_ESP32S31_KORVO_1
    for (uint32_t channel = 0; channel < 2; ++channel) {
        struct wendy_sensor_link_stats stats;
        if (wendy_sensor_link_get_stats(channel, &stats) != ESP_OK)
            continue;
        ESP_LOGI(TAG, "WENDY_BENCH {\"test\":\"sensor\",\"channel\":%" PRIu32
                 ",\"time_us\":%" PRId64 ",\"frames_submitted\":%" PRIu64
                 ",\"frames_completed\":%" PRIu64 ",\"bytes_submitted\":%" PRIu64
                 ",\"capture_errors\":%" PRIu64 ",\"queue_rejected\":%" PRIu64
                 ",\"capture_time_us\":%" PRIu64 ",\"capture_time_max_us\":%" PRIu64
                 ",\"completion_time_us\":%" PRIu64 ",\"completion_time_max_us\":%" PRIu64 "}",
                 channel, esp_timer_get_time(), stats.frames_submitted, stats.frames_completed,
                 stats.bytes_submitted, stats.capture_errors, stats.queue_rejected,
                 stats.capture_time_us, stats.capture_time_max_us,
                 stats.completion_time_us, stats.completion_time_max_us);
    }
#endif
}

// Each call remains observable even with LTO enabled. The external case is
// larger than the data cache; the internal case deliberately measures hot RAM.
static void __attribute__((noinline)) copy_block(void *dst, const void *src, size_t bytes)
{
    memcpy(dst, src, bytes);
    __asm__ volatile("" ::: "memory");
}

static bool benchmark_copy(const char *memory, uint32_t caps, size_t bytes)
{
    enum { ITERATIONS = 32 };
    uint8_t *src = heap_caps_aligned_alloc(64, bytes, caps | MALLOC_CAP_8BIT);
    uint8_t *dst = heap_caps_aligned_alloc(64, bytes, caps | MALLOC_CAP_8BIT);
    bool ok = false;
    if (!src || !dst) {
        ESP_LOGE(TAG, "WENDY_BENCH {\"test\":\"memcpy\",\"memory\":\"%s\","
                 "\"ok\":false,\"error\":\"allocation\"}", memory);
        goto done;
    }
    for (size_t i = 0; i < bytes; ++i)
        src[i] = (uint8_t)(i * 37 + 11);
    copy_block(dst, src, bytes);
    int64_t started = esp_timer_get_time();
    for (int i = 0; i < ITERATIONS; ++i)
        copy_block(dst, src, bytes);
    int64_t elapsed = esp_timer_get_time() - started;
    ok = elapsed > 0 && memcmp(dst, src, bytes) == 0;
    ESP_LOGI(TAG, "WENDY_BENCH {\"test\":\"memcpy\",\"memory\":\"%s\","
             "\"block_bytes\":%zu,\"iterations\":%d,\"elapsed_us\":%" PRId64
             ",\"ok\":%s}", memory, bytes, ITERATIONS, elapsed, ok ? "true" : "false");
done:
    heap_caps_free(src);
    heap_caps_free(dst);
    return ok;
}

static bool benchmark_convolution(void)
{
    enum { CHANNELS = 32, INPUT_BYTES = 10 * 10 * CHANNELS,
           FILTER_BYTES = CHANNELS * CHANNELS, ITERATIONS = 32 };
    const data_dims_t input_dims = { .width = 10, .height = 10, .channels = CHANNELS, .extra = 1 };
    const data_dims_t filter_dims = { .width = 1, .height = 1, .channels = CHANNELS, .extra = 1 };
    const data_dims_t output_dims = input_dims;
    const conv_params_t params = {
        .in_offset = 0, .out_offset = 0, .stride = { 1, 1 },
        .padding = { 0, 0 }, .dilation = { 1, 1 }, .activation = { -128, 127 },
    };
    int32_t shifts[CHANNELS], multipliers[CHANNELS], bias[CHANNELS];
    const quant_data_t quant = { .shift = shifts, .mult = multipliers };
    const uint32_t caps = MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT;
    int8_t *input = heap_caps_aligned_alloc(16, INPUT_BYTES, caps);
    int8_t *filter = heap_caps_aligned_alloc(16, FILTER_BYTES, caps);
    int8_t *reference = heap_caps_aligned_alloc(16, INPUT_BYTES, caps);
    int8_t *optimized = heap_caps_aligned_alloc(16, INPUT_BYTES, caps);
    int scratch_size = esp_nn_get_conv_scratch_size(&input_dims, &filter_dims, &output_dims, &params);
    void *scratch = scratch_size > 0 ? heap_caps_aligned_alloc(16, scratch_size, caps) : NULL;
    bool ok = false;
    if (!input || !filter || !reference || !optimized || scratch_size < 0 || (scratch_size && !scratch)) {
        ESP_LOGE(TAG, "WENDY_BENCH {\"test\":\"conv_int8_1x1\",\"ok\":false,\"error\":\"allocation\"}");
        goto done;
    }
    for (int i = 0; i < INPUT_BYTES; ++i)
        input[i] = (int8_t)(i % 31 - 15);
    for (int i = 0; i < FILTER_BYTES; ++i)
        filter[i] = (int8_t)((i * 7) % 15 - 7);
    for (int i = 0; i < CHANNELS; ++i) {
        shifts[i] = -4;
        multipliers[i] = 0x40000000;
        bias[i] = i - 16;
    }
    esp_nn_set_conv_scratch_buf(scratch);
    esp_nn_conv_s8_ansi(&input_dims, input, &filter_dims, filter, bias,
                        &output_dims, reference, &params, &quant);
    esp_nn_conv_s8(&input_dims, input, &filter_dims, filter, bias,
                   &output_dims, optimized, &params, &quant);
    if (memcmp(reference, optimized, INPUT_BYTES) != 0) {
        ESP_LOGE(TAG, "WENDY_BENCH {\"test\":\"conv_int8_1x1\",\"ok\":false,\"error\":\"output_mismatch\"}");
        goto done;
    }

    int64_t started = esp_timer_get_time();
    for (int i = 0; i < ITERATIONS; ++i)
        esp_nn_conv_s8_ansi(&input_dims, input, &filter_dims, filter, bias,
                            &output_dims, reference, &params, &quant);
    int64_t ansi_us = esp_timer_get_time() - started;
    // Let other tasks run between batches; timing includes normal preemption.
    vTaskDelay(1);
    started = esp_timer_get_time();
    for (int i = 0; i < ITERATIONS; ++i)
        esp_nn_conv_s8(&input_dims, input, &filter_dims, filter, bias,
                       &output_dims, optimized, &params, &quant);
    int64_t pie_us = esp_timer_get_time() - started;
    ok = ansi_us > 0 && pie_us > 0 && memcmp(reference, optimized, INPUT_BYTES) == 0;
    ESP_LOGI(TAG, "WENDY_BENCH {\"test\":\"conv_int8_1x1\",\"core\":%d,"
             "\"iterations\":%d,\"ansi_us\":%" PRId64 ",\"pie_us\":%" PRId64
             ",\"ok\":%s}", xPortGetCoreID(), ITERATIONS, ansi_us, pie_us, ok ? "true" : "false");
done:
    esp_nn_set_conv_scratch_buf(NULL);
    heap_caps_free(scratch);
    heap_caps_free(input);
    heap_caps_free(filter);
    heap_caps_free(reference);
    heap_caps_free(optimized);
    return ok;
}

static void benchmark_task(void *unused)
{
    (void)unused;
    vTaskDelay(pdMS_TO_TICKS(10000));
    report_heap();
    bool internal_ok = benchmark_copy("internal", MALLOC_CAP_INTERNAL, 16 * 1024);
    vTaskDelay(1);
    bool psram_ok = benchmark_copy("psram", MALLOC_CAP_SPIRAM, 256 * 1024);
    vTaskDelay(1);
    bool convolution_ok = benchmark_convolution();
    ESP_LOGI(TAG, "WENDY_BENCH {\"test\":\"complete\",\"ok\":%s}",
             internal_ok && psram_ok && convolution_ok ? "true" : "false");
    for (;;) {
        report_heap();
        vTaskDelay(pdMS_TO_TICKS(5000));
    }
}

esp_err_t wendy_benchmark_start(void)
{
    // S31's PIE coprocessor is only available on Core 1. A low priority keeps
    // management and sensor tasks responsive during this opt-in workload.
    return xTaskCreatePinnedToCore(benchmark_task, "wendy_bench", 4096, NULL,
                                  tskIDLE_PRIORITY + 1, NULL, 1) == pdPASS
        ? ESP_OK : ESP_ERR_NO_MEM;
}
