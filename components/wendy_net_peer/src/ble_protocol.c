/* SPDX-License-Identifier: Apache-2.0 */
#include "wendy_net_ble_protocol.h"
#include "wendy_net_peer_protocol.h"
#include "wendy_pki_crypto.h"
#include <stdio.h>
#include <string.h>

int wn_ble_default_scope_init(struct wn_ble_scope *scope,const char *tenant)
{
    uint8_t uuid[16];char canonical[37],network[64];
    if(!tenant || wn_uuid_parse(tenant,uuid))return -1;
    wn_uuid_format(uuid,canonical);
    snprintf(network,sizeof network,"tenant:%s:default",canonical);
    return wn_ble_scope_init(scope,canonical,network);
}
int wn_ble_scope_init(struct wn_ble_scope *scope, const char *tenant,
                      const char *network)
{
    uint8_t uuid[16], hash[32], nonzero = 0;
    if (!scope || !tenant || !network || !network[0] || strlen(network) > 128 ||
        wn_uuid_parse(tenant, uuid) ||
        wendy_pki_sha256((const uint8_t *)network, strlen(network), hash))
        return -1;
    for (unsigned i = 0; i < 16; i++)
        nonzero |= uuid[i];
    if (!nonzero)
        return -1;
    for (unsigned i = 0; i < 16; i++)
        scope->tenant_wire[i] = uuid[15 - i];
    memcpy(scope->network_hash, hash, 2);
    return 0;
}
int wn_ble_adv_write(const struct wn_ble_scope *scope, const char *device,
                     uint16_t psm, uint8_t out[WN_BLE_ADVERTISEMENT_SIZE])
{
    return wn_ble_adv_write_capabilities(scope,device,psm,WN_BLE_NATIVE_ACCEPTING|WN_BLE_TIME_RELAY,out);
}
int wn_ble_adv_write_capabilities(const struct wn_ble_scope *scope,const char *device,
    uint16_t psm,uint8_t capabilities,uint8_t out[WN_BLE_ADVERTISEMENT_SIZE])
{
    uint8_t uuid[16], nonzero = 0;
    if (!scope || !device || !out || psm < 128 || psm > 255 ||
        wn_uuid_parse(device, uuid))
        return -1;
    for (unsigned i = 0; i < 16; i++)
        nonzero |= uuid[i];
    if (!nonzero)
        return -1;
    out[0] = 2;
    out[1] = 1;
    out[2] = 6; /* General discovery, BLE only. */
    out[3] = 27;
    out[4] = 0x21; /* 128-bit ServiceData. */
    memcpy(out + 5, scope->tenant_wire, 16);
    out[21] = WN_BLE_ADVERTISEMENT_VERSION;
    out[22] = capabilities;
    wn_put16(out + 23, psm);
    memcpy(out + 25, scope->network_hash, 2);
    memcpy(out + 27, uuid, 4);
    return WN_BLE_ADVERTISEMENT_SIZE;
}
bool wn_ble_adv_read(const struct wn_ble_scope *scope, const void *bytes,
                     size_t size, struct wn_ble_hint *hint)
{
    if (!hint)
        return false;
    memset(hint, 0, sizeof *hint);
    if (!scope || !bytes || !size || size > 1650)
        return false;
    const uint8_t *data = bytes;
    struct wn_ble_hint result = {0};
    bool found = false;
    while (size)
    {
        unsigned n = *data++;
        size--;
        if (!n)
            continue; /* Padding between primary and scan-response data. */
        if (n > size)
            return false;
        uint8_t type = data[0];
        if ((type == 0x06 || type == 0x07) && (n - 1) % 16)
            return false;
        if (type == 0x21)
        {
            if (n < 17)
                return false;
            if (!memcmp(data + 1, scope->tenant_wire, 16))
            {
                if (found || n != 27 || data[17] != WN_BLE_ADVERTISEMENT_VERSION ||
                    memcmp(data + 21, scope->network_hash, 2))
                    return false;
                uint16_t psm = wn_get16(data + 19);
                if (psm < 128 || psm > 255)
                    return false;
                result.psm = psm;
                result.capabilities=data[18];
                memcpy(result.device_hint, data + 23, 4);
                found = true;
            }
        }
        data += n;
        size -= n;
    }
    if (found)
        *hint = result;
    return found;
}
