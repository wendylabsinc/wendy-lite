#pragma once

#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

#define MIC_SAMPLE_RATE_HZ 16000
#define MIC_READ_SAMPLES 320

/* Reserve the PDM peripheral before networking allocates DMA memory. */
esp_err_t mic_init(void);
/* Releases the PDM peripheral after startup fails, before capture starts. */
void mic_deinit(void);
esp_err_t mic_start(void);
esp_err_t mic_read(int16_t *buffer, size_t samples, size_t *bytes_read);
void mic_stop(void);
