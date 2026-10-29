/* Normal fragmented-datagram burst, FIFO ownership and idle/reset footprint. */
#include "wendy_net_packet_queue.h"
#include "wendy_net_peer_protocol.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
static unsigned active;
static void *allocate(size_t n){void *p=malloc(n);if(p)active++;return p;}
static void release(void *p){assert(active);active--;free(p);}
int main(void)
{
    struct wnpq q;wnpq_init(&q,4,allocate,release);assert(!active && !q.count);
    unsigned char input[WN_MTU],output[WN_MTU];
    size_t sizes[]={1320,1320,1320,328},n;
    for(unsigned part=0;part<4;part++){
        memset(input,(int)part,sizeof input);input[0]=0x60;
        assert(!wnpq_push(&q,input,sizes[part]));
    }
    assert(active==4 && q.count==4);
    /* An ordinary busy downstream carrier borrows the first packet repeatedly
     * without consuming it or reserving another payload. */
    unsigned char *head=wnpq_front(&q,&n);assert(head && n==sizes[0]);
    assert(wnpq_front(&q,&n)==head && active==4 && q.count==4);
    /* A later ordinary packet waits until the burst has made room. */
    assert(wnpq_push(&q,input,1280)==1);
    memset(input,0xff,sizeof input);
    for(unsigned part=0;part<4;part++){
        assert(wnpq_pop(&q,output,&n)==1 && n==sizes[part] && output[0]==0x60);
        for(size_t i=1;i<n;i++)assert(output[i]==part);
    }
    assert(!active && !q.count && !q.head && !q.tail);
    assert(!wnpq_pop(&q,output,&n) && !n);
    assert(!wnpq_push(&q,input,1280));assert(!wnpq_push(&q,input,1280));
    wnpq_reset(&q);assert(!active && !q.count && !q.head && !q.tail);
    assert(!wnpq_push(&q,input,1280));wnpq_reset(&q);assert(!active);
    puts("Normal IPv6 fragment burst/FIFO/reset owns zero idle packet allocations");return 0;
}
