#pragma once
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"
#define V4L2_PIX_FMT_UYVY 1
typedef void *mosaico_camera_handle_t;
typedef struct { unsigned width, height, frame_timeout_ms; } mosaico_camera_config_t;
#define MOSAICO_CAMERA_DEFAULT_CONFIG() {0}
typedef struct {
    const void *data;
    size_t size;
    uint32_t index, width, height, bytes_per_line, pixel_format;
} mosaico_camera_frame_t;
esp_err_t mosaico_camera_new(const mosaico_camera_config_t *, mosaico_camera_handle_t *);
esp_err_t mosaico_camera_open(mosaico_camera_handle_t);
esp_err_t mosaico_camera_start_stream(mosaico_camera_handle_t);
esp_err_t mosaico_camera_stop_stream(mosaico_camera_handle_t);
esp_err_t mosaico_camera_del(mosaico_camera_handle_t);
esp_err_t mosaico_camera_get_frame(mosaico_camera_handle_t, mosaico_camera_frame_t *);
esp_err_t mosaico_camera_return_frame(mosaico_camera_handle_t, const mosaico_camera_frame_t *);
