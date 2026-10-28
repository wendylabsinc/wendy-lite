#include "wendy_net_ble_protocol.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    struct wn_ble_scope scope, other;
    const char *tenant = "2558fd76-afc7-466e-9613-6b715296a526";
    const char *device = "7cd512eb-eb0c-4f68-b752-148e804e3d11";
    assert(!wn_ble_scope_init(&scope, tenant, "default"));
    uint8_t adv[WN_BLE_ADVERTISEMENT_SIZE], corrupt[2*WN_BLE_ADVERTISEMENT_SIZE];
    assert(wn_ble_adv_write(&scope, device, 129, adv) == WN_BLE_ADVERTISEMENT_SIZE);
    const uint8_t wire[] = {0x26, 0xa5, 0x96, 0x52, 0x71, 0x6b, 0x13, 0x96,
                            0x6e, 0x46, 0xc7, 0xaf, 0x76, 0xfd, 0x58, 0x25};
    assert(!memcmp(adv + 5, wire, 16));
    struct wn_ble_hint hint;
    assert(wn_ble_adv_read(&scope, adv, WN_BLE_ADVERTISEMENT_SIZE, &hint));
    assert(hint.psm == 129 && !memcmp(hint.device_hint, "\x7c\xd5\x12\xeb", 4));
    for (unsigned i = 0; i < WN_BLE_ADVERTISEMENT_SIZE; i++)
        assert(!wn_ble_adv_read(&scope, adv, i, &hint));
    memcpy(corrupt, adv, WN_BLE_ADVERTISEMENT_SIZE);
    memcpy(corrupt + WN_BLE_ADVERTISEMENT_SIZE, adv, WN_BLE_ADVERTISEMENT_SIZE);
    assert(!wn_ble_adv_read(&scope, corrupt, sizeof corrupt, &hint));
    assert(!hint.psm);
    memcpy(corrupt, adv, WN_BLE_ADVERTISEMENT_SIZE);
    corrupt[21] = 2;
    assert(!wn_ble_adv_read(&scope, corrupt, WN_BLE_ADVERTISEMENT_SIZE, &hint));
    memcpy(corrupt, adv, WN_BLE_ADVERTISEMENT_SIZE);
    corrupt[23] = 1;
    assert(!wn_ble_adv_read(&scope, corrupt, WN_BLE_ADVERTISEMENT_SIZE, &hint));
    memcpy(corrupt, adv, WN_BLE_ADVERTISEMENT_SIZE);
    corrupt[24] = 127;
    assert(!wn_ble_adv_read(&scope, corrupt, WN_BLE_ADVERTISEMENT_SIZE, &hint));
    assert(!wn_ble_scope_init(&other, "3558fd76-afc7-466e-9613-6b715296a526",
                              "default"));
    assert(!wn_ble_adv_read(&other, adv, WN_BLE_ADVERTISEMENT_SIZE, &hint));
    assert(!wn_ble_scope_init(&other, tenant, "other"));
    assert(!wn_ble_adv_read(&other, adv, WN_BLE_ADVERTISEMENT_SIZE, &hint));
    assert(wn_ble_adv_write(&scope, device, 127, adv) < 0);
    assert(wn_ble_scope_init(&scope, "00000000-0000-0000-0000-000000000000",
                             "default") < 0);
    for (unsigned i = 0; i < WN_BLE_ADVERTISEMENT_SIZE; i++)
        printf("%02x", adv[i]);
    puts("");
    return 0;
}
