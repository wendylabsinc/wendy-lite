#include "wendy_net_ble_protocol.h"
#include "wendy_net_peer_protocol.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    struct wn_ble_scope scope;
    assert(!wn_ble_default_scope_init(&scope,"22f35004-d638-4b5c-869f-b815974d6eae"));
    uint8_t advertisement[WN_BLE_ADVERTISEMENT_SIZE];
    assert(wn_ble_adv_write(&scope,"fbf0f32d-431d-47d9-8907-629f0edc5828",129,
                            advertisement)==WN_BLE_ADVERTISEMENT_SIZE);
    /* Same vector as WendyOS TestNormalDefaultNetworkAdvertisementForLite. */
    const uint8_t payload[]={1,3,0,129,0x05,0xdd,0xfb,0xf0,0xf3,0x2d};
    assert(!memcmp(advertisement+21,payload,sizeof payload));
    struct wn_ble_hint hint;
    assert(wn_ble_adv_read(&scope,advertisement,sizeof advertisement,&hint));
    assert(hint.psm==129 && !memcmp(hint.device_hint,payload+6,4));
    /* Same BlueZ AD shape as the lab capture, with the explicit v1 payload. */
    const uint8_t bluez_primary[]={0x1b,0x21,0xae,0x6e,0x4d,0x97,0x15,0xb8,
        0x9f,0x86,0x5c,0x4b,0x38,0xd6,0x04,0x50,0xf3,0x22,
        1,3,0,129,0x05,0xdd,0xfb,0xf0,0xf3,0x2d};
    assert(wn_ble_adv_read(&scope,bluez_primary,sizeof bluez_primary,&hint));
    assert(hint.psm==129 && hint.capabilities==3 && !memcmp(hint.device_hint,payload+6,4));
    struct wn_selection selection;wn_selection_init(&selection);
    struct wn_candidate candidate={.medium=WN_BLE,.port=129,.cost=8256,.ble_capabilities=hint.capabilities};
    strcpy(candidate.address,"ble:0:aa:bb:cc:dd:ee:01");
    int slot=wn_candidate_seen(&selection,&candidate,1000);assert(slot>=0);
    unsigned order[WN_CANDIDATES];assert(wn_candidate_order(&selection,1000,7,order)==1);
    assert(wn_candidate_time(&selection,1000,0)==slot);
    assert(wn_ble_adv_write_capabilities(&scope,"fbf0f32d-431d-47d9-8907-629f0edc5828",129,
        WN_BLE_TIME_RELAY,advertisement)==WN_BLE_ADVERTISEMENT_SIZE);
    assert(wn_ble_adv_read(&scope,advertisement,sizeof advertisement,&hint));
    candidate.ble_capabilities=hint.capabilities;assert(wn_candidate_seen(&selection,&candidate,1001)==slot);
    assert(wn_candidate_order(&selection,1001,7,order)==0); /* Latest busy replaces ready. */
    assert(wn_candidate_time(&selection,1001,0)==slot); /* Encrypted time remains discoverable. */
    assert(!wn_candidate_hold(&selection,(unsigned)slot));candidate.ble_capabilities=3|0x80;
    assert(wn_candidate_seen(&selection,&candidate,1002)==slot && selection.candidates[slot].holds==1);
    wn_candidate_release(&selection,(unsigned)slot);
    assert(wn_candidate_order(&selection,1002,7,order)==1);
    candidate.ble_capabilities=WN_BLE_NATIVE_ACCEPTING;assert(wn_candidate_seen(&selection,&candidate,1003)==slot);
    assert(wn_candidate_time(&selection,1003,0)<0);
    puts("BLE v1: ready/busy/ready, unknown capability, native admission and independent time discovery");
    return 0;
}
