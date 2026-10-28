#include "netif_effect.h"
#include <assert.h>
#include <stdio.h>
int main(void)
{
    struct wnne_effect effect;wnne_init(&effect,WNNE_DOWN);
    assert(wnne_idle(&effect));wnne_desire(&effect,WNNE_UP);
    assert(wnne_next(&effect,0) && effect.submitted==WNNE_UP);
    /* Ordinary TCP/IP mailbox pressure is a retry, never an actor wait. */
    wnne_submitted(&effect,false,0);
    assert(wnne_deadline(&effect)==10000 && !wnne_next(&effect,9999));
    assert(wnne_next(&effect,10000));wnne_submitted(&effect,true,10000);
    unsigned unrelated=0;
    for(int64_t now=10001;now<20000;now++){assert(!wnne_next(&effect,now));unrelated++;}
    assert(unrelated==9999 && !wnne_idle(&effect));
    /* OFF cannot mutate the callback's UP payload or free its root. An
     * intervening DOWN coalesces to the final REMOVE without a second job. */
    wnne_desire(&effect,WNNE_DOWN);wnne_desire(&effect,WNNE_REMOVED);
    assert(effect.submitted==WNNE_UP && !wnne_next(&effect,20000));
    wnne_complete(&effect,0);
    assert(wnne_next(&effect,20001) && effect.applied==WNNE_UP && effect.submitted==WNNE_REMOVED);
    wnne_submitted(&effect,true,20001);assert(!wnne_idle(&effect));
    wnne_complete(&effect,0);assert(!wnne_next(&effect,20002) && wnne_idle(&effect));
    assert(effect.applied==WNNE_REMOVED);
    /* A normal SDK failure is also deferred with finite retry. */
    wnne_init(&effect,WNNE_DOWN);wnne_desire(&effect,WNNE_UP);
    assert(wnne_next(&effect,0));wnne_submitted(&effect,true,0);wnne_complete(&effect,-1);
    assert(!wnne_next(&effect,1) && wnne_deadline(&effect)==10001);
    assert(wnne_next(&effect,10001));
    /* Callback completion may precede the nonblocking submit's return. */
    wnne_complete(&effect,0);wnne_submitted(&effect,true,10001);
    assert(!wnne_next(&effect,10002) && wnne_idle(&effect));
    puts("Serial netif effects preserve unrelated progress, finite retry and OFF callback ownership");
    return 0;
}
