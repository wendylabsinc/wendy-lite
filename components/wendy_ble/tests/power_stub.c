/* Advertising/transport tests run without a controller. Power policy is checked separately on real
 * controllers; these no-ops keep the transport tests independent. */
#include <stdint.h>
void wendy_ble_power_init(void) {}
int wendy_ble_power_host_sync(void) { return 0; }
void wendy_ble_power_host_reset(void) {}
int8_t wendy_ble_power_advertising_request(void) { return 127; }
void wendy_ble_power_advertising_selected(int8_t actual) { (void)actual; }
void wendy_ble_power_connected(uint16_t handle) { (void)handle; }
void wendy_ble_power_disconnected(uint16_t handle) { (void)handle; }

int wendy_ble_power_apply_advertising(void) { return 0; }

void wendy_ble_power_advertising_started(void) {}
