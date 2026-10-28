/* Positive counterpart of WendyOS CandidateQueue: healthy shuffle, recent
 * failures last/oldest first, success, expiry and ordinary eligibility. */
#include "wendy_net_peer_protocol.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static int seen(struct wn_selection *s,unsigned endpoint,int64_t now)
{
    struct wn_candidate hint={.medium=WN_LAN,.port=43024,.cost=128};
    snprintf(hint.address,sizeof hint.address,"192.0.2.%u",endpoint+1);
    int index=wn_candidate_seen(s,&hint,now);assert(index>=0);return index;
}
static unsigned position(const unsigned *order,unsigned count,unsigned slot)
{
    for(unsigned i=0;i<count;i++)if(order[i]==slot)return i;
    return count;
}
int main(void)
{
    struct wn_selection s;wn_selection_init(&s);unsigned slots[4],order[WN_CANDIDATES];
    for(unsigned i=0;i<4;i++)slots[i]=(unsigned)seen(&s,i,1000);
    wn_candidate_failed(&s,slots[0],1000);wn_candidate_failed(&s,slots[1],2000);
    bool firsts[4]={false};
    for(uint32_t seed=1;seed<=40;seed++){
        unsigned count=wn_candidate_order(&s,7000,seed,order);assert(count==4);
        assert(order[2]==slots[0] && order[3]==slots[1]);
        firsts[order[0]]=true;
    }
    assert(firsts[slots[2]] && firsts[slots[3]]);
    wn_candidate_failed(&s,slots[0],8000);
    assert(s.candidates[slots[0]].retry_ms==13000);
    assert(wn_candidate_order(&s,14000,7,order)==4);
    assert(order[2]==slots[1] && order[3]==slots[0]);
    const char *peer="20000000-0000-4000-8000-000000000002";
    assert(!wn_candidate_commit(&s,slots[0],peer));s.active=-1;
    assert(!s.candidates[slots[0]].failures && !s.candidates[slots[0]].failed_ms &&
           !s.candidates[slots[0]].retry_ms);
    assert(wn_candidate_order(&s,14000,8,order)==4);
    assert(position(order,4,slots[0])<position(order,4,slots[1]));
    /* Ordinary repeated sightings retain the failure receipt, while the
     * scheduling penalty expires exactly30s after that failure. */
    for(unsigned i=0;i<4;i++)assert(seen(&s,i,31000)==(int)slots[i]);
    assert(s.candidates[slots[1]].failed_ms==2000);
    memset(firsts,0,sizeof firsts);
    for(uint32_t seed=1;seed<=80;seed++){
        assert(wn_candidate_order(&s,32000,seed,order)==4);firsts[order[0]]=true;
    }
    for(unsigned i=0;i<4;i++)assert(firsts[slots[i]]);
    /* Skips/capacity checks do not call failed(): ordering is a pure function. */
    s.candidates[slots[2]].passive=true;s.active=(int)slots[3];
    struct wn_selection before=s;
    assert(wn_candidate_order(&s,32000,9,order)==2);
    assert(!memcmp(&before,&s,sizeof s));
    assert(position(order,2,slots[2])==2 && position(order,2,slots[3])==2);
    assert(!wn_candidate_order(&s,61000,9,order)); /* Sightings expire. */
    /* A real failure at monotonic time0 has the same penalty and fixed floor. */
    struct wn_selection boot;wn_selection_init(&boot);
    unsigned a=(unsigned)seen(&boot,0,0),b=(unsigned)seen(&boot,1,0);
    wn_candidate_failed(&boot,a,0);
    assert(wn_candidate_order(&boot,4999,3,order)==1 && order[0]==b);
    assert(wn_candidate_order(&boot,5000,3,order)==2 && order[0]==b && order[1]==a);
    assert(seen(&boot,0,29999)==(int)a && seen(&boot,1,29999)==(int)b);
    bool a_first=false,b_first=false;
    for(uint32_t seed=1;seed<=40;seed++){
        assert(wn_candidate_order(&boot,30000,seed,order)==2);
        a_first|=order[0]==a;b_first|=order[0]==b;
    }
    assert(a_first && b_first);
    /* One fixed-capacity table is the complete candidate/failure history. */
    for(unsigned i=0;i<WN_CANDIDATES;i++){
        int index=seen(&boot,i,70000);wn_candidate_failed(&boot,(unsigned)index,70000);
        assert(boot.candidates[index].retry_ms==75000);
    }
    assert(wn_candidate_order(&boot,75000,99,order)==WN_CANDIDATES);
    printf("CandidateQueue: healthy shuffle,30s oldest-failure penalty,5s floor, history%u, state%zu bytes\n",
        WN_CANDIDATES,sizeof boot);
    return 0;
}
