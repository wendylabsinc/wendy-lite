/* SPDX-License-Identifier: Apache-2.0 */
#include "esp_log.h"
#include "host/ble_gap.h"
#include "host/ble_hs.h"
#include "wendy_ble.h"
#include "wendy_ble_mesh.h"
#include <stdatomic.h>

static atomic_uint selected;
static const char *TAG = "net-phy";
/* ESP-IDF v6.0.3's own BLE throughput example uses this controller hook.
 * It chooses the default Coded scheme before any connections are created.
 * Per-link HCI preferences are still set explicitly below. */
#if CONFIG_IDF_TARGET_ESP32C5 || CONFIG_IDF_TARGET_ESP32C6
extern void esp_ble_switch_phy_coded(bool phy_500k);
#endif
void wble_mesh_set_profile(unsigned value) { atomic_store(&selected, value); }
unsigned wble_mesh_profile(void) { return atomic_load(&selected); }
const char *wble_mesh_profile_name(void) {
    unsigned p = wble_mesh_profile();
    return p == 1 ? "coded-s2" : p == 2 ? "coded-s8" : "normal";
}
int wble_mesh_profile_sync(void) {
    unsigned p = wble_mesh_profile();
    if (p > 2)
        return BLE_HS_ENOTSUP;
#if !CONFIG_BT_NIMBLE_EXT_ADV_V2 || !(CONFIG_IDF_TARGET_ESP32C5 || CONFIG_IDF_TARGET_ESP32C6)
    if (p)
        return BLE_HS_ENOTSUP;
#endif
#if !(CONFIG_IDF_TARGET_ESP32C5 || CONFIG_IDF_TARGET_ESP32C6)
    /* Older 1M-only controllers need no PHY command, and may reject it. */
    if (!p)
        return 0;
#endif
    /* Core 5.4 Advertising Coding Selection (Host Support), feature bit 40.
     * Enables separate S2/S8 values in received extended advertising reports. */
    int feature = ble_gap_set_host_feat(40, 1);
    uint8_t phy = p ? BLE_GAP_LE_PHY_CODED_MASK : BLE_GAP_LE_PHY_1M_MASK;
    int rc = ble_gap_set_prefered_default_le_phy(phy, phy);
#if CONFIG_IDF_TARGET_ESP32C5 || CONFIG_IDF_TARGET_ESP32C6
    if (!rc && p)
        esp_ble_switch_phy_coded(p == 1);
#endif
    ESP_LOGI(TAG, "profile=%s host_coding_selection=%d default_phy=%u result=%d",
             wble_mesh_profile_name(), feature, phy, rc);
    /* Coding-specific report metadata is optional in this experimental
     * controller. Required transmit coding is independently enforced by the
     * extended advertising command; discovery still uses only Coded PHY. */
    return rc;
}
void wble_mesh_profile_connected(uint16_t handle) {
    unsigned p = wble_mesh_profile();
    uint8_t phy = p ? BLE_GAP_LE_PHY_CODED_MASK : BLE_GAP_LE_PHY_1M_MASK;
    int rc = ble_gap_set_prefered_le_phy(handle, phy, phy,
                                         p == 1   ? BLE_GAP_LE_PHY_CODED_S2
                                         : p == 2 ? BLE_GAP_LE_PHY_CODED_S8
                                                  : 0);
    uint8_t tx = 0, rx = 0;
    int read = ble_gap_read_le_phy(handle, &tx, &rx);
    ESP_LOGI(TAG,
             "connected handle=%u profile=%s requested=%d read=%d actual_tx=%u "
             "actual_rx=%u",
             handle, wble_mesh_profile_name(), rc, read, tx, rx);
}
void wble_mesh_profile_event(const void *value) {
    const struct ble_gap_event *e = value;
    if (e->type == BLE_GAP_EVENT_PHY_UPDATE_COMPLETE) {
        ESP_LOGI(TAG,
                 "updated handle=%u status=%d actual_tx=%u actual_rx=%u "
                 "requested_profile=%s",
                 e->phy_updated.conn_handle, e->phy_updated.status, e->phy_updated.tx_phy,
                 e->phy_updated.rx_phy, wble_mesh_profile_name());
    }
}
