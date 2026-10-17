#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "esp_err.h"
#include "wendy_com_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Starts the shared camera/audio sender. Capture drivers must be initialized first. */
esp_err_t cam_loop_init(void);

/* Reserves the SDK's single stream. Returns BUSY while another subscription
 * owns it or the matching stream is stopping. */
enum wcom_sensor_link_result cam_loop_start(int client_id, uint32_t channel_id);

/* Stops the stream matching (client_id, channel_id) as soon as possible,
 * or cancels it if it was only latched and not yet started. No-op if
 * neither matches. */
void cam_loop_stop(int client_id, uint32_t channel_id);

#ifdef __cplusplus
}
#endif
