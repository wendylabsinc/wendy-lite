/* Ordinary low-memory cache retirement while one upload remains active. */
#include "wendy_net_gossip.h"
#include "test_sha256.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
struct observation {struct wg_id own;unsigned evictions,gone,data;};
static unsigned shared_refs;
static void retain(const void *p){assert(p);shared_refs++;}
static void release(const void *p){assert(p && shared_refs);shared_refs--;}
static bool protected(void *context,const struct wg_id *id)
{struct observation *o=context;return id->type==o->own.type && !memcmp(id->hash,o->own.hash,32);}
static void evicted(void *context,const struct wg_id *id,const void *p,size_t size)
{struct observation *o=context;assert(p && size && !protected(context,id));o->evictions++;}
static int emit(void *context,const struct wg_message *m)
{struct observation *o=context;if(m->op==WG_GONE)o->gone++;if(m->op==WG_DATA){o->data++;for(size_t i=0;i<m->size;i++)assert(m->data[i]==2);}return 0;}
static int complete(void *context,const struct wg_id *id,const void *data,size_t n)
{(void)context;(void)id;(void)data;(void)n;return 0;}
int main(void)
{
 struct observation seen={0};struct wg_pool p;struct wg_session routes,services;
 struct wg_config cfg={.identify=identify,.context=&seen,.objects=16,.pending=4,
  .bytes=8192,.fifo=true,.uploads=1,.protected_object=protected,.evicted=evicted};
 assert(!wg_init(&p,&cfg));assert(!wg_open(&p,&routes,1));assert(!wg_open(&p,&services,2));
 uint8_t data[1536],shared[512];struct wg_id pinned,optional,relay,last;
 memset(data,1,sizeof data);assert(!wg_offer(&p,1,data,512,10000,1000,&seen.own));
 memset(data,2,sizeof data);assert(!wg_offer(&p,2,data,sizeof data,10000,1001,&pinned));
 memset(data,3,sizeof data);assert(!wg_offer(&p,2,data,1024,10000,1002,&optional));
 memset(data,4,sizeof data);assert(!wg_offer(&p,1,data,512,10000,1003,&relay));
 memset(shared,5,sizeof shared);assert(!wg_offer_shared(&p,2,shared,sizeof shared,10000,1004,&last,retain,release));
 assert(shared_refs==1);
 struct wg_message want={.id=pinned,.op=WG_WANT,.request=1};
 assert(!wg_receive(&services,&want,1005,emit,complete,&seen));
 assert(wg_reclaim(&p,2048)==2048 && seen.evictions==3 && !shared_refs);
 assert(p.payload_bytes==2048 && p.object_count==5 && p.serving==1);
 assert(!wg_reclaim(&p,4096)); /* Remaining local proof and upload stay resident. */
 for(unsigned i=0;i<5;i++){assert(!wg_poll(&routes,1006+i,emit,&seen));assert(!wg_poll(&services,1006+i,emit,&seen));}
 assert(seen.gone==3 && seen.data==2 && !p.serving);
 memset(data,3,sizeof data);struct wg_id again;
 assert(wg_offer(&p,2,data,1024,10000,1012,&again)==2);
 struct wg_message have={.id=optional,.op=WG_HAVE};
 assert(!wg_receive(&services,&have,1013,emit,complete,&seen) && !p.pending_count);
 assert(wg_reclaim(&p,1)==1536 && p.payload_bytes==512 && seen.evictions==4);
 assert(!wg_poll(&services,1014,emit,&seen) && seen.gone==4);
 wg_close(&services);wg_close(&routes);wg_deinit(&p);
 puts("pressure reclaim preserves local proof/upload, releases FIFO/shared bodies, sends GONE and forgets exact digests");
}
