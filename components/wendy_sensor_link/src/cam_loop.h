#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "esp_err.h"
#include "wendy_com_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Starts the shared camera/audio sender. Capture drivers must be initialized first. */
esp_err_t cam_loop_init(void);

/* Reserves a sender. Korvo has one per channel; XIAO keeps one shared sender.
 * Returns BUSY while another subscription owns it or it is stopping. */
enum wcom_sensor_link_result cam_loop_start(int client_id, uint32_t channel_id);
/* Atomically validates and reserves all requested channels. */
enum wcom_sensor_link_result cam_loop_start_many(int client_id, const uint32_t *channel_ids, size_t count);

/* Stops the stream matching (client_id, channel_id) as soon as possible,
 * or cancels it if it was only latched and not yet started. No-op if
 * neither matches. */
void cam_loop_stop(int client_id, uint32_t channel_id);

#ifdef __cplusplus
}
#endif
