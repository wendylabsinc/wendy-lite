/* Ten ordinary announcements over one carrier, one active body at a time. */
#include "wendy_net_gossip.h"
#include "test_sha256.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
struct observed {struct wg_message want;unsigned wants,complete,unavailable;};
static int emit(void *ctx,const struct wg_message *m)
{struct observed *o=ctx;if(m->op==WG_WANT){o->want=*m;o->wants++;}if(m->op==WG_UNAVAILABLE)o->unavailable++;return 0;}
static int complete(void *ctx,const struct wg_id *id,const void *bytes,size_t n)
{struct observed *o=ctx;(void)id;assert(n==100 && ((const uint8_t*)bytes)[0]==o->complete);o->complete++;return 0;}
struct deferred {uint64_t requests[2];bool ready[2];unsigned completed[2];};
static int deferred_emit(void *context,const struct wg_message *message)
{struct deferred *d=context;if(message->op==WG_WANT)d->requests[message->id.hash[0]&1]=message->request;return 0;}
static int deferred_complete(void *context,const struct wg_id *id,const void *bytes,size_t size)
{
    struct deferred *d=context;(void)id;assert(size==100);unsigned index=((const uint8_t*)bytes)[0];assert(index<2);
    if(!d->ready[index])return WG_DEFER;
    d->completed[index]++;return 0;
}
static void owned_completion_first(void)
{
    struct wg_pool pool;struct wg_session session;struct wg_config config={.identify=identify,.objects=8,.pending=8,.bytes=4096,.downloads=2};
    assert(!wg_init(&pool,&config) && !wg_open(&pool,&session,1));struct deferred state={0};struct wg_id ids[2];uint64_t requests[2];
    uint8_t bytes[2][100];
    for(unsigned i=0;i<2;i++){
        memset(bytes[i],i,100);ids[i].type=1;assert(!identify(NULL,1,bytes[i],100,ids[i].hash));
        struct wg_message message={.id=ids[i],.op=WG_HAVE};
        memset(state.requests,0,sizeof state.requests);assert(!wg_receive(&session,&message,1000+i,deferred_emit,deferred_complete,&state));
        requests[i]=state.requests[ids[i].hash[0]&1];assert(requests[i]);
    }
    for(unsigned i=0;i<2;i++){
        struct wg_message message={.id=ids[i],.op=WG_DATA,.request=requests[i],.total=100,.data=bytes[i],.size=100};
        assert(!wg_receive(&session,&message,1003+i,deferred_emit,deferred_complete,&state));
    }
    /* The second completed callback is now at the shared head. Its older CPU
     * owner can still finish first, without reallocating either bounded body. */
    assert(pool.pending_count==2);state.ready[0]=true;
    assert(wg_resume_id(&session,&ids[0],deferred_complete,&state)==1);
    assert(state.completed[0]==1 && !state.completed[1] && pool.pending_count==1);
    state.ready[1]=true;assert(wg_resume_id(&session,&ids[1],deferred_complete,&state)==1);
    assert(state.completed[1]==1 && !pool.pending_count && !pool.payload_bytes);
    assert(wg_resume_id(&session,&ids[0],deferred_complete,&state)==WG_RESUME_MISSING);
    wg_close(&session);wg_deinit(&pool);
}
int main(void)
{
    struct wg_pool p;struct wg_session session,another;struct wg_id ids[10];
    struct wg_config config={.identify=identify,.objects=16,.pending=16,.bytes=8192,.downloads=1,.uploads=1};
    assert(!wg_init(&p,&config) && !wg_open(&p,&session,2) && !wg_open(&p,&another,1));
    struct observed o={0};uint8_t data[100];
    for(unsigned i=0;i<10;i++){
        memset(data,i,sizeof data);ids[i].type=2;assert(!identify(NULL,2,data,sizeof data,ids[i].hash));
        struct wg_message have={.id=ids[i],.op=WG_HAVE};
        assert(!wg_receive(&session,&have,1000,emit,complete,&o));
    }
    assert(o.wants==1 && p.pending_count==10 && !p.payload_bytes);
    for(unsigned i=0;i<10;i++){
        if(i)assert(!wg_poll(&session,1001+i,emit,&o));
        assert(o.wants==i+1 && !memcmp(o.want.id.hash,ids[i].hash,32));
        memset(data,i,sizeof data);
        struct wg_message m={.id=ids[i],.op=WG_DATA,.request=o.want.request,.total=100,.size=100,.data=data};
        assert(!wg_receive(&session,&m,1001+i,emit,complete,&o));
        assert(!p.payload_bytes && p.pending_count==9-i);
    }
    assert(o.complete==10);
    /* The upload budget covers both category sessions on the same node. */
    struct wg_id a,b;
    assert(!wg_offer(&p,2,data,sizeof data,61000,2000,&a));
    assert(!wg_offer(&p,1,data,sizeof data,61000,2000,&b));
    struct wg_message want={.id=a,.op=WG_WANT,.request=1};
    assert(!wg_receive(&session,&want,2001,emit,complete,&o) && p.serving==1);
    want.id=b;want.request=2;
    assert(!wg_receive(&another,&want,2002,emit,complete,&o) && o.unavailable==1 && p.serving==1);
    assert(!wg_poll(&session,2003,emit,&o) && !p.serving);
    want.request=3;
    assert(!wg_receive(&another,&want,2004,emit,complete,&o) && p.serving==1);
    assert(!wg_poll(&another,2005,emit,&o) && !p.serving);
    wg_close(&session);wg_close(&another);wg_deinit(&p);
    owned_completion_first();
    puts("Ten hints drain FIFO with one download; uploads are bounded across categories");
}
