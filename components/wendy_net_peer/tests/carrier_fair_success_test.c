/* Ordinary mixed mesh catch-up: Babel, metadata and TCP/IP share finite space. */
#include "wendy_net_carrier.h"
#include "wendy_net_peer_protocol.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
static unsigned allocations;
void *wendy_net_malloc(size_t n){void *p=malloc(n);if(p)allocations++;return p;}
void *wendy_net_calloc(size_t n,size_t bytes){void *p=calloc(n,bytes);if(p)allocations++;return p;}
void wendy_net_free(void *p){if(p){assert(allocations);allocations--;free(p);}}
struct wire {uint8_t data[32768];size_t size;unsigned writes;bool block;const void *retry;size_t retry_size;};
static ssize_t input(void *ctx,void *out,size_t size){(void)ctx;(void)out;(void)size;return -2;}
static ssize_t output(void *ctx,const void *data,size_t size)
{
    struct wire *w=ctx;w->writes++;
    if(w->retry){assert(data==w->retry && size==w->retry_size);w->retry=NULL;}
    if(w->block || w->writes%5==0){w->block=false;w->retry=data;w->retry_size=size;return -3;}
    if(size>7)size=7;assert(w->size+size<=sizeof w->data);
    memcpy(w->data+w->size,data,size);w->size+=size;return (ssize_t)size;
}
static int receive(void *ctx,const void *data,size_t size,bool control)
{(void)ctx;(void)data;(void)size;(void)control;assert(0);return -1;}
static void init(struct wnc_carrier *c,struct wire *w,uint8_t *scratch,unsigned slots)
{
    struct wnc_io io={w,input,output};assert(!allocations);
    assert(!wnc_init(c,&io,scratch,WN_DATAGRAM_MAX,8192,65536));
    assert(!wnc_fair_scheduler(c,slots));assert(!allocations && !c->queued);
}
static void enqueue(struct wnc_carrier *c,char kind,unsigned id)
{
    uint8_t data[]={kind=='R' ? 2:kind=='I' ? 1:(uint8_t)'M',(uint8_t)kind,(uint8_t)id};
    int r=kind=='I' ? wnc_enqueue(c,data,sizeof data,false):wnc_enqueue_priority(c,data,sizeof data,kind=='M');assert(!r);
}
static void drain(struct wnc_carrier *c)
{
    for(unsigned i=0;c->queued && i<10000;i++)assert(wnc_pump(c,1000+i,receive,NULL)>=0);
    assert(!c->queued && !c->head && !c->tail && !allocations);
    for(unsigned k=0;k<WNC_CLASSES;k++)assert(!c->class_head[k] && !c->class_tail[k] && !c->class_frames[k] && !c->class_bytes[k]);
}
static void order(const struct wire *w,const char *expected)
{
    size_t at=0;unsigned count=0;
    while(at<w->size){const uint8_t *p=w->data+at;size_t n=wn_get32(p+1);assert(at+5+n<=w->size);
        const uint8_t *body=p+5;if(p[0]==1){assert(n>=4 && wn_get32(body)==n-4);body+=4;}
        assert(body[1]==expected[count]);count++;at+=5+n;
    }
    assert(count==strlen(expected));
}
static bool saw_ip(const struct wire *w)
{
    size_t at=0;unsigned frames=0;
    while(at+5<=w->size){const uint8_t *p=w->data+at;size_t n=wn_get32(p+1);if(at+5+n>w->size)break;
        const uint8_t *body=p+5;if(p[0]==1)body+=4;
        frames++;if(body[1]=='I'){assert(frames<=4);return true;}at+=5+n;
    }
    return false;
}
int main(void)
{
    uint8_t scratch[WN_DATAGRAM_MAX];struct wire wire={0};struct wnc_carrier c;
    init(&c,&wire,scratch,8);
    for(unsigned i=0;i<3;i++){enqueue(&c,'M',i);enqueue(&c,'I',i);enqueue(&c,'R',i);}
    drain(&c);order(&wire,"RMRIRMIMI");wnc_deinit(&c);
    /* A write that accepted zero bytes already belongs to TLS. Later routing
     * and metadata may not replace its pointer/length or interleave bytes. */
    wire=(struct wire){.block=true};init(&c,&wire,scratch,4);enqueue(&c,'I',0);
    assert(!wnc_pump(&c,1,receive,NULL));enqueue(&c,'M',0);enqueue(&c,'R',0);enqueue(&c,'I',1);enqueue(&c,'R',1);
    drain(&c);order(&wire,"IRMRI");
    wnc_deinit(&c);
    /* A full metadata catch-up must still admit one maximum Babel datagram
     * and one complete fragmented IP packet without growing the ceiling. */
    wire=(struct wire){0};init(&c,&wire,scratch,8);
    uint8_t metadata[1024]={0},babel[WN_DATAGRAM_MAX]={2},packet[WN_MTU]={0x60};packet[6]=59;packet[7]=64;wn_put16(packet+4,WN_MTU-40);
    unsigned accepted=0;while(!wnc_enqueue_priority(&c,metadata,sizeof metadata,true))accepted++;
    assert(accepted && !wnc_enqueue_priority(&c,babel,sizeof babel,false));
    assert(!wnc_enqueue_packet(&c,packet,sizeof packet,1) && c.queued<=8192);
    drain(&c);wnc_deinit(&c);
    /* Replenishing metadata and routing producers cannot postpone a waiting
     * TCP/IP frame: one routing frame then another class, metadata/IP rotate. */
    wire=(struct wire){0};init(&c,&wire,scratch,8);enqueue(&c,'I',0);
    for(unsigned i=0;!saw_ip(&wire) && i<1000;i++){
        uint8_t m[]={'M','M',(uint8_t)i},r[]={2,'R',(uint8_t)i};
        int a=wnc_enqueue_priority(&c,m,sizeof m,true),b=wnc_enqueue_priority(&c,r,sizeof r,false);
        assert((!a || a==WNC_LIMIT) && (!b || b==WNC_LIMIT));
        assert(wnc_pump(&c,1000+i,receive,NULL)>=0);
    }
    assert(saw_ip(&wire));wnc_deinit(&c);assert(!allocations);
    /* Both actual SRAM/PSRAM slot bounds are independent of the byte budget. */
    for(unsigned slots=4;slots<=8;slots+=4){wire=(struct wire){0};init(&c,&wire,scratch,slots);
        for(unsigned i=0;i<slots;i++)enqueue(&c,'R',i);
        assert(wnc_enqueue_priority(&c,babel,2,false)==WNC_LIMIT);enqueue(&c,'I',0);enqueue(&c,'M',0);
        drain(&c);wnc_deinit(&c);
    }
    /* Ordinary packet admission can fail after its first fragment. Restore
     * both ownership and class FIFOs, retaining the prior queued IP intact. */
    wire=(struct wire){0};init(&c,&wire,scratch,8);enqueue(&c,'I',0);
    size_t frame_header=c.queued-8;
    uint8_t filler[6000]={0};size_t metadata_size=8192-2*WNC_CLASS_RESERVE-frame_header-9;
    assert(metadata_size<=sizeof filler && !wnc_enqueue_priority(&c,filler,metadata_size,true));
    size_t before=c.queued;unsigned objects=allocations;
    assert(wnc_enqueue_packet(&c,packet,sizeof packet,2)==WNC_LIMIT);
    assert(c.queued==before && allocations==objects && c.class_frames[WNC_IP]==1);
    drain(&c);wnc_deinit(&c);
    /* Normal OFF while several queues own frames releases every allocation. */
    wire=(struct wire){0};init(&c,&wire,scratch,4);enqueue(&c,'R',0);enqueue(&c,'M',0);enqueue(&c,'I',0);
    assert(allocations==3);wnc_deinit(&c);assert(!allocations && !c.head && !c.queued);
    puts("Bounded Babel/metadata/IP fairness, admission, partial retry and OFF ownership pass");
}
