/* SPDX-License-Identifier: Apache-2.0
 * ESP-NOW has one receive callback per device. This shares it: each user
 * names the leading bytes of its own frames and receives exactly those.
 * Callbacks run in the Wi-Fi task with the driver's own arguments, rx_ctrl
 * and its timestamp included, with no copy, queue or task switch in between.
 * Wendy Net's ESP-NOW carrier is one such user (frames start with "WNEN").
 */
#pragma once
#include "esp_err.h"
#include "esp_now.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WENDY_ESPNOW_USERS 4
#define WENDY_ESPNOW_PREFIX_MAX 8

/* Starts ESP-NOW when this is the first user (Wi-Fi must be initialized),
 * makes sure the broadcast peer exists, and delivers every received frame
 * that begins with these bytes to cb. Subscribing the same callback again
 * replaces its prefix. Users add their own unicast peers and call
 * esp_now_send themselves; nobody else may call esp_now_register_recv_cb or
 * esp_now_deinit. cb must not block and must not call these two functions. */
esp_err_t wendy_espnow_subscribe(const void *prefix, size_t size, esp_now_recv_cb_t cb);
/* Returns once no call into cb is running. ESP-NOW stops with its last user. */
void wendy_espnow_unsubscribe(esp_now_recv_cb_t cb);

#ifdef __cplusplus
}
#endif
