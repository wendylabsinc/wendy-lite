/* Ordinary bounded category caches, active upload and proactive withdrawal. */
#include "wendy_net_gossip.h"
#include "test_sha256.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
struct observed {struct wg_id gone;unsigned gone_count,frames,evictions;bool busy;};
static void evicted(void *ctx,const struct wg_id *id,const void *data,size_t size)
{struct observed *o=ctx;assert(size==1536 && ((const uint8_t*)data)[0]==2);o->evictions++;o->gone=*id;}
static int emit(void *ctx,const struct wg_message *m)
{
    struct observed *o=ctx;
    if(m->op==WG_GONE){if(o->busy){o->busy=false;return 1;}assert(!memcmp(m->id.hash,o->gone.hash,32));o->gone_count++;}
    if(m->op==WG_DATA){for(size_t i=0;i<m->size;i++)assert(m->data[i]==1);o->frames++;}
    return 0;
}
static int complete(void *ctx,const struct wg_id *id,const void *data,size_t n)
{(void)ctx;(void)id;(void)data;(void)n;return 0;}
static bool local_route(void *ctx,const struct wg_id *id)
{(void)ctx;return id->type==1;}
static void reserved_metadata(void)
{
    struct wg_config config={.identify=identify,.objects=3,.pending=4,.bytes=4096,
        .reserve_objects=1,.critical_object=local_route};
    struct wg_pool p;struct wg_id id,own;uint8_t data[64];memset(data,1,sizeof data);
    assert(!wg_init(&p,&config));
    assert(!wg_offer(&p,2,data,sizeof data,61000,1000,&id));data[0]=2;
    assert(!wg_offer(&p,2,data,sizeof data,61000,1000,&id));data[0]=3;
    assert(wg_offer(&p,2,data,sizeof data,61000,1000,&id)==1);
    assert(!wg_offer(&p,1,data,sizeof data,61000,1000,&own));
    wg_forget(&p,&own);data[0]=4;
    assert(!wg_offer(&p,1,data,sizeof data,61000,1000,&own));
    assert(p.object_count==3);wg_deinit(&p);
}
int main(void)
{
    reserved_metadata();
    struct observed o={0};struct wg_pool pool;struct wg_session services,routes;
    struct wg_config config={.identify=identify,.context=&o,.objects=32,.pending=16,
        .bytes=4096,.downloads=1,.uploads=1,.fifo=true,.type_bytes={1024,3072},.evicted=evicted};
    assert(!wg_init(&pool,&config) && !wg_open(&pool,&services,2) && !wg_open(&pool,&routes,1));
    uint8_t bytes[1536];struct wg_id first,second,third,route;
    memset(bytes,1,sizeof bytes);assert(!wg_offer(&pool,2,bytes,sizeof bytes,10000,1000,&first));
    memset(bytes,2,sizeof bytes);assert(!wg_offer(&pool,2,bytes,sizeof bytes,10000,1001,&second));
    memset(bytes,4,sizeof bytes);assert(!wg_offer(&pool,1,bytes,512,10000,1002,&route));
    struct wg_message want={.id=first,.op=WG_WANT,.request=1};
    assert(!wg_receive(&services,&want,1003,emit,complete,&o));
    /* Oldest first is pinned; only the next service is evicted. */
    memset(bytes,3,sizeof bytes);assert(!wg_offer(&pool,2,bytes,sizeof bytes,10000,1004,&third));
    assert(o.evictions==1 && pool.payload_bytes==3584 && pool.type_payload[0]==512 && pool.type_payload[1]==3072);
    o.busy=true;
    assert(wg_poll(&services,1005,emit,&o)==1 && !o.gone_count && !o.frames);
    assert(!wg_poll(&services,1005,emit,&o) && o.gone_count==1 && !o.frames);
    assert(!wg_poll(&services,1006,emit,&o) && !wg_poll(&services,1007,emit,&o) && o.frames==2);
    assert(!pool.serving);
    memset(bytes,2,sizeof bytes);struct wg_id again;
    assert(wg_offer(&pool,2,bytes,sizeof bytes,20000,1010,&again)==2);
    struct wg_message have={.id=second,.op=WG_HAVE};
    assert(!wg_receive(&services,&have,1011,emit,complete,&o) && !pool.pending_count);
    wg_forget(&pool,&second); /* Supersession cannot undo sticky eviction. */
    assert(wg_offer(&pool,2,bytes,sizeof bytes,20000,1012,&again)==2);
    assert(!wg_poll(&routes,1013,emit,&o) && o.gone_count==1); /* Independent category. */
    wg_prune(&pool,130001);assert(!pool.object_count && !pool.payload_bytes && !pool.type_payload[0] && !pool.type_payload[1]);
    wg_close(&services);wg_close(&routes);wg_deinit(&pool);
    puts("FIFO skips an active upload, sends GONE, retires exact digest and bounds each category");
}
