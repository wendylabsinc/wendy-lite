/* Ordinary certificate-cache miss releases a deferred artifact supplier. */
#include "wendy_net_gossip.h"
#include "test_sha256.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
struct observation {unsigned wants,completed;uint64_t request;bool defer;};
static int emit(void *context,const struct wg_message *m)
{struct observation *o=context;if(m->op==WG_WANT){o->wants++;o->request=m->request;}return 0;}
static int complete(void *context,const struct wg_id *id,const void *bytes,size_t size)
{struct observation *o=context;(void)id;assert(size==512 && ((const uint8_t*)bytes)[0]==7);o->completed++;return o->defer ? WG_DEFER:0;}
int main(void)
{
 struct wg_pool pool;struct wg_session first,other;
 struct wg_config config={.identify=identify,.objects=4,.pending=4,.bytes=8192};
 assert(!wg_init(&pool,&config) && !wg_open(&pool,&first,3) && !wg_open(&pool,&other,3));
 uint8_t body[512];memset(body,7,sizeof body);
 struct wg_message have={.op=WG_HAVE,.id.type=3};assert(!identify(NULL,3,body,sizeof body,have.id.hash));
 struct observation a={.defer=true},b={0};
 assert(!wg_receive(&first,&have,1000,emit,complete,&a) && a.wants==1);
 assert(!wg_receive(&other,&have,1001,emit,complete,&b) && !b.wants);
 struct wg_message data={.op=WG_DATA,.id=have.id,.request=a.request,.total=sizeof body,.data=body,.size=sizeof body};
 assert(!wg_receive(&first,&data,1002,emit,complete,&a) && a.completed==1 && pool.payload_bytes==sizeof body);
 wg_discard(&first,&have.id);assert(!pool.payload_bytes);
 assert(!wg_poll(&first,1003,emit,&a) && a.wants==1);
 assert(!wg_poll(&other,1003,emit,&b) && b.wants==1);
 data.request=b.request;assert(!wg_receive(&other,&data,1004,emit,complete,&b) && b.completed==1);
 wg_close(&first);wg_close(&other);wg_deinit(&pool);
 assert(!pool.payload_bytes && !pool.metadata_bytes);
 puts("Deferred artifact supplier retired immediately; alternate progresses with no negative receipt or retained bytes");
}
