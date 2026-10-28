/* Ordinary discovery crowding: a ninth endpoint can replace a fresh unused
 * hint, while physical owners and recent failure receipts stay stable. */
#include "wendy_net_peer_protocol.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static struct wn_candidate hint(unsigned endpoint)
{
    struct wn_candidate c={.medium=WN_LAN,.port=43024,.cost=128};
    snprintf(c.address,sizeof c.address,"192.0.2.%u",endpoint+1);return c;
}
static int seen(struct wn_selection *s,unsigned endpoint,int64_t now)
{
    struct wn_candidate c=hint(endpoint);return wn_candidate_seen(s,&c,now);
}
int main(void)
{
    /* TLS can identify a blind BLE hint before hello declines a redundant
     * connection. Preserve that name through ordinary reports and close while
     * keeping admission, retry history and physical ownership unchanged. */
    struct wn_selection radio;wn_selection_init(&radio);
    struct wn_candidate blind={.medium=WN_BLE,.port=129,.cost=8192};
    strcpy(blind.address,"ble:0:02:00:00:00:00:01");
    int authenticated=wn_candidate_seen(&radio,&blind,1000);assert(authenticated>=0);
    assert(!wn_candidate_hold(&radio,(unsigned)authenticated));
    wn_candidate_failed(&radio,(unsigned)authenticated,1100);
    struct wn_candidate before_auth=radio.candidates[authenticated];
    const char *verified="00000000-0000-4000-8000-000000000001";
    assert(!wn_candidate_authenticated(&radio,(unsigned)authenticated,verified));
    assert(radio.active==-1 && radio.candidates[authenticated].holds==before_auth.holds);
    assert(radio.candidates[authenticated].retry_ms==before_auth.retry_ms &&
           radio.candidates[authenticated].failures==before_auth.failures);
    assert(wn_candidate_seen(&radio,&blind,1200)==authenticated);
    assert(!strcmp(radio.candidates[authenticated].device,verified));
    wn_candidate_release(&radio,(unsigned)authenticated);
    assert(wn_candidate_seen(&radio,&blind,1300)==authenticated);
    assert(!strcmp(radio.candidates[authenticated].device,verified) && radio.active==-1);
    struct wn_selection s;wn_selection_init(&s);unsigned slots[WN_CANDIDATES];
    for(unsigned i=0;i<WN_CANDIDATES;i++){
        int index=seen(&s,i,1000+i);assert(index>=0);slots[i]=(unsigned)index;
    }
    assert(!wn_candidate_hold(&s,slots[0]) && !wn_candidate_hold(&s,slots[0]));
    assert(!wn_candidate_hold(&s,slots[1]));
    wn_candidate_failed(&s,slots[2],1100);
    int newest=seen(&s,WN_CANDIDATES,2000);
    assert(newest==(int)slots[3]); /* First unheld row without a cooldown. */
    assert(s.candidates[slots[2]].failed_ms==1100);
    for(unsigned i=WN_CANDIDATES+1;i<WN_CANDIDATES+10;i++){
        int index=seen(&s,i,2200+i);assert(index>=0);
        assert(index!=(int)slots[0] && index!=(int)slots[1] && index!=(int)slots[2]);
    }
    /* Repeated hints update sightings, never a physical owner's expectation. */
    struct wn_candidate changed=hint(1);changed.cost=512;changed.passive=true;
    assert(wn_candidate_seen(&s,&changed,3000)==(int)slots[1]);
    assert(s.candidates[slots[1]].cost==128 && !s.candidates[slots[1]].passive);
    wn_candidate_release(&s,slots[0]);assert(s.candidates[slots[0]].holds==1);
    assert(seen(&s,WN_CANDIDATES+11,3500)!=(int)slots[0]);
    wn_candidate_release(&s,slots[0]);assert(!s.candidates[slots[0]].holds);
    assert(seen(&s,WN_CANDIDATES+12,4000)==(int)slots[0]);
    /* A completed attempt releases its owner but retains the 30s receipt. */
    wn_candidate_failed(&s,slots[1],5000);wn_candidate_release(&s,slots[1]);
    for(unsigned i=WN_CANDIDATES+13;i<3*WN_CANDIDATES+13;i++)
        assert(seen(&s,i,34000+i)!=(int)slots[1]);
    assert(s.candidates[slots[1]].failed_ms==5000);
    assert(seen(&s,3*WN_CANDIDATES+13,35000)==(int)slots[1]);
    struct wn_selection busy;wn_selection_init(&busy);
    for(unsigned i=0;i<WN_CANDIDATES;i++){
        int index=seen(&busy,i,1000+i);assert(index>=0);
        assert(!wn_candidate_hold(&busy,(unsigned)index));
    }
    struct wn_selection before=busy;
    assert(seen(&busy,WN_CANDIDATES,2000)==-1 && !memcmp(&busy,&before,sizeof busy));
    wn_candidate_release(&busy,0);
    assert(seen(&busy,WN_CANDIDATES,2001)==0);
    unsigned order[WN_CANDIDATES];
    assert(wn_candidate_order(&busy,2001,42,order)==1 && order[0]==0);
    printf("Candidate admission: %u fresh hints accept a newcomer; held/cooldown rows preserved; state%zu bytes\n",
        WN_CANDIDATES,sizeof s);
    return 0;
}
