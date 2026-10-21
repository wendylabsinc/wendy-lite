#pragma once
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"
typedef void *jpeg_encoder_handle_t;
typedef struct { int timeout_ms; } jpeg_encode_engine_cfg_t;
typedef struct { int buffer_direction; } jpeg_encode_memory_alloc_cfg_t;
typedef struct {
    unsigned width, height;
    int src_type, sub_sample, image_quality;
} jpeg_encode_cfg_t;
#define JPEG_ENC_ALLOC_OUTPUT_BUFFER 1
#define JPEG_ENCODE_IN_FORMAT_YUV422 1
#define JPEG_DOWN_SAMPLING_YUV422 1
esp_err_t jpeg_new_encoder_engine(const jpeg_encode_engine_cfg_t *, jpeg_encoder_handle_t *);
esp_err_t jpeg_del_encoder_engine(jpeg_encoder_handle_t);
void *jpeg_alloc_encoder_mem(size_t, const jpeg_encode_memory_alloc_cfg_t *, size_t *);
esp_err_t jpeg_encoder_process(jpeg_encoder_handle_t, const jpeg_encode_cfg_t *,
                               const void *, size_t, uint8_t *, size_t, uint32_t *);
