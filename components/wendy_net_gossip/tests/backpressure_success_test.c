/* One ordinary artifact transfer resumes after transient output queue pressure. */
#include "wendy_net_gossip.h"
#include "test_sha256.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
struct endpoint {struct wg_message message;uint8_t bytes[WG_CHUNK];unsigned sent,complete;bool busy,defer;const void *retained;};
static int emit(void *ctx,const struct wg_message *m)
{
    struct endpoint *e=ctx;if(e->busy)return 1;
    e->message=*m;e->sent++;
    if(m->size){memcpy(e->bytes,m->data,m->size);e->message.data=e->bytes;}return 0;
}
static int complete(void *ctx,const struct wg_id *id,const void *p,size_t n)
{
    (void)id;struct endpoint *e=ctx;const char expected[]="ordinary route artifact";
    assert(n==sizeof expected && !memcmp(p,expected,n));e->complete++;
    if(e->retained)assert(p==e->retained);else e->retained=p;
    return e->defer ? WG_DEFER:0;
}
int main(void)
{
    struct wg_config cfg={.identify=identify,.objects=4,.pending=4,.bytes=8192};
    struct wg_pool source,receiver;struct wg_session a,b;
    assert(!wg_init(&source,&cfg) && !wg_init(&receiver,&cfg));
    assert(!wg_open(&source,&a,1) && !wg_open(&receiver,&b,1));
    const char body[]="ordinary route artifact";struct wg_id id;
    assert(!wg_offer(&source,1,body,sizeof body,61000,1000,&id));
    struct endpoint tx={0},rx={.busy=true};struct wg_message have={.id=id,.op=WG_HAVE};
    assert(wg_receive(&b,&have,1000,emit,complete,&rx)==1 && !rx.sent);
    rx.busy=false;assert(!wg_poll(&b,1001,emit,&rx));assert(rx.sent==1 && rx.message.op==WG_WANT);
    assert(!wg_receive(&a,&rx.message,1001,emit,complete,&tx));
    tx.busy=true;assert(wg_poll(&a,1002,emit,&tx)==1 && !tx.sent);
    tx.busy=false;assert(!wg_poll(&a,1003,emit,&tx));assert(tx.sent==1 && tx.message.offset==0);
    rx.defer=true;
    assert(!wg_receive(&b,&tx.message,1003,emit,complete,&rx) && rx.complete==1);
    assert(receiver.pending_count==1 && receiver.payload_bytes==sizeof body);
    unsigned requests=rx.sent;
    for(unsigned i=0;i<10;i++){
        assert(!wg_resume(&b,complete,&rx));
        assert(receiver.pending_count==1 && receiver.payload_bytes==sizeof body && rx.sent==requests);
    }
    rx.defer=false;assert(wg_resume(&b,complete,&rx)==1);
    assert(!receiver.pending_count && !receiver.payload_bytes);
    wg_close(&a);wg_close(&b);wg_deinit(&source);wg_deinit(&receiver);
    puts("Ordinary HAVE/WANT/DATA transfer resumes without losing progress");return 0;
}
