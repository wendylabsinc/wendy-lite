#pragma once

#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"
#ifdef ESP_PLATFORM
#include "sdkconfig.h"
#endif

#define MIC_SAMPLE_RATE_HZ 16000
#if CONFIG_WENDY_SENSOR_LINK_ESP32S31_KORVO_1
#define MIC_CHANNELS 2
#else
#define MIC_CHANNELS 1
#endif
#define MIC_READ_SAMPLES (320 * MIC_CHANNELS)
/* One frame carries a 20 ms block plus whatever queued up behind it while the
 * previous frame was sent. Korvo reads through esp_codec_dev, which cannot
 * tell what has queued, so it sends block by block. */
#if CONFIG_WENDY_SENSOR_LINK_ESP32S31_KORVO_1
#define MIC_MAX_READ_SAMPLES MIC_READ_SAMPLES
#else
#define MIC_MAX_READ_SAMPLES (MIC_READ_SAMPLES * 8)
#endif

/* Reserve the board's audio peripheral before networking allocates DMA memory. */
esp_err_t mic_init(void);
/* Releases the PDM peripheral after startup fails, before capture starts. */
void mic_deinit(void);
esp_err_t mic_start(void);
esp_err_t mic_read(int16_t *buffer, size_t samples, size_t *bytes_read);
/* Copies up to samples already captured, without waiting. *bytes_read is 0
 * when nothing has queued, or when the driver cannot tell. */
esp_err_t mic_read_queued(int16_t *buffer, size_t samples, size_t *bytes_read);
void mic_stop(void);
