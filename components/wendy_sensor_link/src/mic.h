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

/* Reserve the board's audio peripheral before networking allocates DMA memory. */
esp_err_t mic_init(void);
/* Releases the PDM peripheral after startup fails, before capture starts. */
void mic_deinit(void);
esp_err_t mic_start(void);
esp_err_t mic_read(int16_t *buffer, size_t samples, size_t *bytes_read);
void mic_stop(void);
