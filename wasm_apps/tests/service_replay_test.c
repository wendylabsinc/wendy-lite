/* Ordinary guest lifecycle: OFF, busy actor, restart during handoff, withdrawal. */
#include "wendy_services.h"
#include <assert.h>
#include <stdio.h>
static uint32_t epoch;
static unsigned publications,withdrawals;
static int busy,restart;
int services_epoch(void){return (int)epoch;}
int services_publish(const void *spec,int size)
{
    assert(spec && size>0 && epoch);publications++;
    if(busy){busy=0;return -2;}
    if(restart){restart=0;epoch++;}
    return 0;
}
int services_withdraw(const void *id,int size)
{assert(id && size>0 && epoch);withdrawals++;return 0;}
int main(void)
{
    const char spec[]="{\"serviceId\":\"temperature\"}";
    wendy_service_replay state={0};
    assert(wendy_service_replay_step(&state,spec,sizeof spec-1,0,0)==-2);
    assert(!publications && !state.epoch);
    epoch=1;
    assert(!wendy_service_replay_step(&state,spec,sizeof spec-1,0,1000));
    assert(publications==1 && state.epoch==1);
    assert(!wendy_service_replay_step(&state,spec,sizeof spec-1,0,2000));
    assert(publications==1); /* Unchanged native incarnation causes no replay. */
    epoch=0;
    assert(wendy_service_replay_step(&state,spec,sizeof spec-1,0,3000)==-2);
    assert(publications==1 && !state.epoch);
    epoch=2;busy=1;
    assert(wendy_service_replay_step(&state,spec,sizeof spec-1,0,4000)==-2);
    assert(!state.epoch && publications==2);
    assert(!wendy_service_replay_step(&state,spec,sizeof spec-1,0,5000));
    assert(state.epoch==2 && publications==3);
    epoch=3;restart=1;
    assert(wendy_service_replay_step(&state,spec,sizeof spec-1,0,6000)==-2);
    assert(!state.epoch && epoch==4 && publications==4);
    assert(!wendy_service_replay_step(&state,spec,sizeof spec-1,0,7000));
    assert(state.epoch==4 && publications==5);
    wendy_service_replay_changed(&state);
    assert(!wendy_service_replay_step(&state,"temperature",11,1,8000));
    assert(withdrawals==1);
    epoch=0;wendy_service_replay_changed(&state);
    assert(wendy_service_replay_step(&state,"temperature",11,1,9000)==-2);
    assert(withdrawals==1); /* Keep the guest ID until a new catalogue signs. */
    epoch=5;
    assert(!wendy_service_replay_step(&state,"temperature",11,1,10000));
    assert(withdrawals==2);
    puts("guest-owned service intent replays only after incarnation changes; busy/restart acknowledgements and withdrawal pass");
}
