/* SPDX-License-Identifier: Apache-2.0
 * WendyOS-compatible discovery hints. No advertisement grants authority.
 */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define WN_BLE_ADVERTISEMENT_SIZE 31
#define WN_BLE_ADVERTISEMENT_VERSION 1
#define WN_BLE_NATIVE_ACCEPTING 1
#define WN_BLE_TIME_RELAY 2
struct wn_ble_scope
{
    uint8_t tenant_wire[16], network_hash[2];
};
struct wn_ble_hint
{
    uint8_t device_hint[4];
    uint16_t psm;
    uint8_t capabilities;
};
int wn_ble_scope_init(struct wn_ble_scope *, const char *tenant,
                      const char *network);
/* WendyOS's default BLE network name is tenant:<canonical UUID>:default. */
int wn_ble_default_scope_init(struct wn_ble_scope *, const char *tenant);
int wn_ble_adv_write(const struct wn_ble_scope *, const char *device,
                     uint16_t psm, uint8_t out[WN_BLE_ADVERTISEMENT_SIZE]);
int wn_ble_adv_write_capabilities(const struct wn_ble_scope *,const char *device,
    uint16_t psm,uint8_t capabilities,uint8_t out[WN_BLE_ADVERTISEMENT_SIZE]);
/* Decode only this live report, never merge fields with cached advertisements.
 * Accept bounded concatenated AD fields; reject duplicate matching ServiceData.
 * The returned UUID prefix is advisory. TLS must authenticate the full UUID.
 */
bool wn_ble_adv_read(const struct wn_ble_scope *, const void *, size_t,
                     struct wn_ble_hint *);
