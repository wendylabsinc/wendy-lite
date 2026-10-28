#include "wendy_net_carrier.h"
#include "wendy_net_peer_protocol.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

struct wire {uint8_t bytes[8192];size_t size,read_at;const void *retry;size_t retry_size;bool first,read_enabled;};
static ssize_t read_idle(void *ctx,void *p,size_t n)
{(void)ctx;(void)p;(void)n;return -2;}
static ssize_t write_partial(void *ctx,const void *p,size_t n)
{
    struct wire *w=ctx;
    if(w->first){w->first=false;w->retry=p;w->retry_size=n;return -3;}
    if(w->retry){assert(p==w->retry && n==w->retry_size);w->retry=NULL;}
    if(n>13)n=13;
    assert(n<=sizeof w->bytes-w->size);memcpy(w->bytes+w->size,p,n);w->size+=n;
    return (ssize_t)n;
}
static int unused(void *ctx,const void *p,size_t n,bool control)
{(void)ctx;(void)p;(void)n;(void)control;assert(0);return -1;}
static ssize_t read_partial(void *ctx,void *p,size_t n)
{
    struct wire *w=ctx;
    if(!w->read_enabled || w->read_at==w->size)return -2;
    if(n>13)n=13;
    if(n>w->size-w->read_at)n=w->size-w->read_at;
    memcpy(p,w->bytes+w->read_at,n);w->read_at+=n;return (ssize_t)n;
}
struct received {unsigned frames;struct wn_assembler packet;};
static int receive_partial(void *ctx,const void *p,size_t n,bool control)
{
    struct received *r=ctx;
    if(r->frames==1)assert(control && n==sizeof "normal control" && !memcmp(p,"normal control",n));
    else if(r->frames==2)assert(!control && n==2 && !memcmp(p,(uint8_t[]){2,42},2));
    else assert(!control && wn_assemble(&r->packet,p,n,10000)==(r->frames==3 ? WN_MTU:0));
    r->frames++;return 0;
}
struct paused {const void *frame;size_t size;unsigned calls;bool ready;};
static int hold_frame(void *ctx,const void *p,size_t n,bool control)
{
    struct paused *paused=ctx;
    (void)control;
    if(!paused->calls){paused->frame=p;paused->size=n;}
    assert(paused->frame==p && paused->size==n);
    paused->calls++;
    return paused->ready ? 0:1;
}
int main(void)
{
    struct wire wire={.first=true};struct wnc_carrier c;
    struct wnc_io io={.context=&wire,.read=read_idle,.write=write_partial};
    uint8_t scratch[WN_DATAGRAM_MAX],packet[WN_MTU]={0x60};
    packet[6]=59;packet[7]=64;wn_put16(packet+4,WN_MTU-40);
    for(unsigned i=40;i<sizeof packet;i++)packet[i]=(uint8_t)i;
    assert(!wnc_init(&c,&io,scratch,sizeof scratch,8192,65536));c.priority_reserve=6144;
    c.stall_timeout_us=30000000;c.frame_timeout_us=90000000;
    assert(!wnc_enqueue_packet(&c,packet,sizeof packet,1));size_t queued=c.queued;
    assert(wnc_enqueue_packet(&c,packet,sizeof packet,2)==WNC_LIMIT && c.queued==queued);
    assert(wnc_pump(&c,1000,unused,NULL)==0); /* Pinned TLS write retry. */
    /* A valid slow encrypted stream resumes after a radio/crypto pause longer
     * than the generic five-second default, retaining exactly the same retry. */
    struct wnc_timeout timeout;
    assert(!wnc_timeout_snapshot(&c,6000000,&timeout));
    const char control[]="normal control";uint8_t babel[]={2,42};
    assert(!wnc_enqueue_priority(&c,control,sizeof control,true));
    assert(!wnc_enqueue_priority(&c,babel,sizeof babel,false));
    for(unsigned i=0;c.queued && i<1000;i++)assert(wnc_pump(&c,6000000+i,unused,NULL)>=0);
    assert(!c.queued && !wire.retry);
    struct wn_assembler a={0};unsigned frame=0;size_t at=0;
    while(at<wire.size){
        const uint8_t *p=wire.bytes+at;size_t n=wn_get32(p+1);assert(at+5+n<=wire.size);
        if(frame==1){assert(p[0]==1 && wn_get32(p+5)==sizeof control);assert(!memcmp(p+9,control,sizeof control));}
        else if(frame==2){assert(p[0]==2 && n==sizeof babel && !memcmp(p+5,babel,n));}
        else {assert(p[0]==2);int r=wn_assemble(&a,p+5,n,10000);assert(r==(frame==3 ? WN_MTU:0));}
        at+=5+n;frame++;
    }
    assert(frame==4 && !memcmp(a.packet,packet,sizeof packet));wnc_deinit(&c);
    /* The same valid frames also survive a six-second pause between their
     * header and body on receive, with no wire reset or lost fragments. */
    struct wnc_io input={.context=&wire,.read=read_partial,.write=write_partial};
    struct received received={0};wire.read_enabled=true;
    assert(!wnc_init(&c,&input,scratch,sizeof scratch,8192,65536));
    c.stall_timeout_us=30000000;c.frame_timeout_us=90000000;
    assert(wnc_pump(&c,1000,receive_partial,&received)==1 && c.header_have==5);
    wire.read_enabled=false;
    assert(wnc_pump(&c,6000000,receive_partial,&received)==0);
    wire.read_enabled=true;
    for(unsigned i=0;wire.read_at<wire.size && i<1000;i++)assert(wnc_pump(&c,6000001+i,receive_partial,&received)>=0);
    assert(received.frames==4 && !memcmp(received.packet.packet,packet,sizeof packet));wnc_deinit(&c);
    /* Local deferred verification retains the charged frame without reading
     * another one, and outgoing control still makes progress on this link. */
    wire=(struct wire){.read_enabled=true};
    wn_put32(wire.bytes+1,8);wire.bytes[0]=1;
    wn_put32(wire.bytes+5,4);memcpy(wire.bytes+9,"have",4);wire.size=13;
    assert(!wnc_init(&c,&input,scratch,sizeof scratch,8192,65536));
    c.stall_timeout_us=30000000;c.frame_timeout_us=90000000;
    struct paused paused={0};
    for(unsigned i=0;!c.rx_paused && i<10;i++)assert(wnc_pump(&c,1000+i,hold_frame,&paused)>=0);
    assert(c.rx_paused && paused.calls==1);
    size_t read_at=wire.read_at;
    assert(!wnc_enqueue_priority(&c,control,sizeof control,true));
    for(unsigned i=0;i<20;i++)assert(wnc_pump(&c,100000000+i,hold_frame,&paused)>=0);
    assert(wire.read_at==read_at && !c.queued && c.rx_paused);
    paused.ready=true;
    /* Disable synthetic input: the test's write buffer is the same object. */
    wire.read_enabled=false;
    assert(wnc_pump(&c,100000100,hold_frame,&paused)>=0 && !c.rx_paused);
    wnc_deinit(&c);
    puts("Priority control, pinned partial writes and complete IP packet delivery pass");return 0;
}
