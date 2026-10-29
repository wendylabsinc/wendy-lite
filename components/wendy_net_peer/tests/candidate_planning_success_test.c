/* Ordinary discovery, dial planning, authenticated admission and retry. */
#include "wendy_net_peer_protocol.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    const char *lower="10000000-0000-4000-8000-000000000001";
    const char *higher="20000000-0000-4000-8000-000000000002";
    struct wn_selection active,passive;
    wn_selection_init(&active);wn_selection_init(&passive);
    struct wn_candidate lan={.address="192.0.2.2",.medium=WN_LAN,.port=43024,.cost=128};
    strcpy(lan.device,higher);
    struct wn_candidate ble={.address="ble:0:02:00:00:00:00:02",.medium=WN_BLE,.ble_capabilities=WN_BLE_NATIVE_ACCEPTING|WN_BLE_TIME_RELAY,.port=129,.cost=8192};
    int a=wn_candidate_seen(&active,&lan,1000),b=wn_candidate_seen(&active,&ble,1000);
    assert(a>=0 && b>=0 && a!=b && wn_candidate_next(&active,1000)==a);
    /* A normal failed LAN attempt leaves BLE eligible, then LAN recovers. */
    wn_candidate_failed(&active,(unsigned)a,1000);
    assert(wn_candidate_next(&active,1001)==b);
    assert(wn_candidate_seen(&active,&lan,1100)==a);
    assert(wn_candidate_next(&active,1100)==b);
    assert(wn_candidate_next(&active,6000)==a);
    assert(!wn_candidate_commit(&active,(unsigned)a,higher));
    assert(active.active==a);

    strcpy(lan.device,lower);lan.passive=true;ble.passive=true;
    int incoming=wn_candidate_seen(&passive,&lan,1000);
    assert(incoming>=0 && wn_candidate_seen(&passive,&ble,1000)>=0);
    assert(wn_candidate_next(&passive,1000)==-1);
    assert(wn_candidate_seen(&passive,&lan,2000)==incoming);
    assert(wn_candidate_next(&passive,2000)==-1);
    /* Passive discovery never prevents an ordinarily authenticated accept. */
    assert(!wn_candidate_commit(&passive,(unsigned)incoming,lower));
    assert(!strcmp(passive.candidates[incoming].device,lower));
    /* Both ends choose the same physical connection when ordinary discovery
     * crosses. Neither side replaces its same-direction incumbent. */
    assert(wn_link_replaces(lower,higher,true,false));
    assert(wn_link_replaces(higher,lower,false,true));
    assert(!wn_link_replaces(lower,higher,false,true));
    assert(!wn_link_replaces(higher,lower,true,false));
    assert(!wn_link_replaces(lower,higher,false,false));
    assert(!wn_link_replaces(higher,lower,true,true));
    /* Full-router mode clears the single-active selector while retaining
     * several links. Repeated normal BLE reports still retain the learned
     * expected peer, including after an ordinary carrier close/cooldown. */
    assert(!wn_candidate_commit(&active,(unsigned)b,higher));
    active.active=-1;
    assert(wn_candidate_seen(&active,&ble,7000)==b);
    assert(!strcmp(active.candidates[b].device,higher));
    wn_candidate_failed(&active,(unsigned)b,7001);
    assert(wn_candidate_seen(&active,&ble,7002)==b);
    assert(!strcmp(active.candidates[b].device,higher));
    assert(active.candidates[b].retry_ms>7002);
    /* An mDNS radio association is not itself a BLE sighting. Its passive
     * placeholder becomes dialable only when the ordinary BLE report arrives. */
    struct wn_selection correlated;wn_selection_init(&correlated);
    struct wn_candidate placeholder=ble;placeholder.passive=true;
    strcpy(placeholder.device,higher);
    int radio=wn_candidate_seen(&correlated,&placeholder,0);assert(radio>=0);
    assert(wn_candidate_next(&correlated,31000)==-1);
    ble.passive=false;
    assert(wn_candidate_seen(&correlated,&ble,32000)==radio);
    assert(!strcmp(correlated.candidates[radio].device,higher));
    assert(!correlated.candidates[radio].passive);
    assert(wn_candidate_next(&correlated,32000)==radio);
    placeholder.passive=false;
    assert(wn_candidate_seen(&correlated,&placeholder,32000)==radio);
    assert(correlated.candidates[radio].seen_ms==32000);
    assert(wn_candidate_next(&correlated,63000)==-1);
    struct wn_selection tri;wn_selection_init(&tri);
    lan.passive=ble.passive=false;
    struct wn_candidate nan={.address="fe80::211:22ff:fe33:4455%3",
        .medium=WN_NAN,.port=35633,.cost=512};
    strcpy(nan.device,lower);
    int tl=wn_candidate_seen(&tri,&lan,1000);
    int tn=wn_candidate_seen(&tri,&nan,1000);
    assert(tl>=0 && tn>=0 && wn_candidate_seen(&tri,&ble,1000)>=0);
    assert(wn_candidate_next(&tri,1000)==tl);
    wn_candidate_failed(&tri,(unsigned)tl,1000);
    assert(wn_candidate_next(&tri,1001)==tn);
    assert(!wn_candidate_commit(&tri,(unsigned)tn,lower));
    /* The retry floor does not prevent a healthy fallback, and once it
     * expires the ordinary lower-cost carrier can replace that attachment. */
    struct wn_selection fallback;wn_selection_init(&fallback);
    struct wn_candidate wifi=lan;strcpy(wifi.device,higher);
    int fast=wn_candidate_seen(&fallback,&wifi,1000);
    int slow=wn_candidate_seen(&fallback,&ble,1000);
    assert(fast>=0 && slow>=0);
    wn_candidate_failed(&fallback,(unsigned)fast,1000);
    assert(wn_candidate_next(&fallback,1001)==slow);
    assert(!wn_candidate_commit(&fallback,(unsigned)slow,higher));
    assert(wn_candidate_next(&fallback,5999)==-1);
    assert(wn_candidate_next(&fallback,6000)==fast);
    assert(!wn_candidate_commit(&fallback,(unsigned)fast,higher));
    assert(wn_candidate_next(&fallback,6001)==-1);
    puts("LAN/BLE candidate planning, normal retry and incoming admission pass");
    return 0;
}
