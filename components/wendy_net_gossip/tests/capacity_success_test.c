/* Ordinary receiver budget refusal and continued delivery on the same link. */
#include "wendy_net_gossip.h"
#include "test_sha256.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
struct observed {struct wg_message want;unsigned wants,completed;};
static int emit(void *ctx,const struct wg_message *m)
{struct observed *o=ctx;if(m->op==WG_WANT){o->want=*m;o->wants++;}return 0;}
static int complete(void *ctx,const struct wg_id *id,const void *data,size_t n)
{struct observed *o=ctx;(void)id;assert(n==100 && ((const uint8_t*)data)[0]==0);o->completed++;return 0;}
static void route_progress_reserve(void)
{
    struct wg_pool pool;struct wg_session service,route;struct observed observed={0};
    struct wg_config cfg={.identify=identify,.objects=8,.pending=8,.bytes=4096,
        .downloads=2,.route_download_reserve=1};
    assert(!wg_init(&pool,&cfg) && !wg_open(&pool,&service,2) && !wg_open(&pool,&route,1));
    struct wg_message first={.op=WG_HAVE,.id.type=2};first.id.hash[0]=1;
    assert(!wg_receive(&service,&first,1,emit,complete,&observed) && observed.wants==1);
    first.id.hash[0]=2;
    assert(!wg_receive(&service,&first,2,emit,complete,&observed) && observed.wants==1);
    first.id.type=1;first.id.hash[0]=3;
    assert(!wg_receive(&route,&first,3,emit,complete,&observed) && observed.wants==2);
    struct wg_progress progress;wg_progress(&pool,&progress);
    assert(progress.active[0]==1 && progress.active[1]==1 && pool.pending_count==3);
    first.id.hash[0]=4;
    assert(!wg_receive(&route,&first,4,emit,complete,&observed) && observed.wants==2);
    assert(!pool.payload_bytes); /* The global two-download bound was not raised. */
    wg_close(&route);wg_close(&service);wg_deinit(&pool);
}
int main(void)
{
    route_progress_reserve();
    struct wg_pool p;struct wg_session s;struct observed o={0};
    struct wg_config cfg={.identify=identify,.objects=16,.pending=4,.bytes=1024,.downloads=1,.uploads=1,.fifo=true};
    assert(!wg_init(&p,&cfg) && !wg_open(&p,&s,2));
    uint8_t bytes[1536];memset(bytes,9,sizeof bytes);
    struct wg_message m={.id.type=2,.op=WG_HAVE};assert(!identify(NULL,2,bytes,sizeof bytes,m.id.hash));
    assert(!wg_receive(&s,&m,1000,emit,complete,&o) && o.wants==1);
    m.op=WG_DATA;m.request=o.want.request;m.data=bytes;m.size=1024;m.total=1536;
    assert(!wg_receive(&s,&m,1001,emit,complete,&o));
    assert(!p.pending_count && !p.payload_bytes && !o.completed);
    m.offset=1024;m.size=512;m.data=bytes+1024;
    assert(!wg_receive(&s,&m,1002,emit,complete,&o)); /* Already queued remainder. */
    memset(bytes,0,100);m=(struct wg_message){.id.type=2,.op=WG_HAVE};
    assert(!identify(NULL,2,bytes,100,m.id.hash));
    assert(!wg_receive(&s,&m,1003,emit,complete,&o) && o.wants==2);
    m.op=WG_DATA;m.request=o.want.request;m.total=m.size=100;m.data=bytes;
    assert(!wg_receive(&s,&m,1004,emit,complete,&o) && o.completed==1 && !p.payload_bytes);
    wg_close(&s);wg_deinit(&p);
    puts("A body beyond receiver capacity is declined without losing the next ordinary delivery");
}
