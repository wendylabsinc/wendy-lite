/* Shared ordinary hints: only their suppliers spend admission work, while
 * downloads remain globally bounded and each owner retains its four slots. */
#include "wendy_net_gossip.h"
#include "test_sha256.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
struct state {bool demand;unsigned demand_calls;};
struct peer {unsigned wants;struct wg_message first,last;};
static bool want(void *ctx,const struct wg_id *id,uint64_t now)
{struct state *s=ctx;(void)id;(void)now;s->demand_calls++;return s->demand;}
static int emit(void *ctx,const struct wg_message *m)
{struct peer *p=ctx;if(m->op==WG_WANT){if(!p->wants)p->first=*m;p->last=*m;p->wants++;}return 0;}
static int complete(void *ctx,const struct wg_id *id,const void *bytes,size_t n)
{(void)ctx;(void)id;assert(n==32 && ((const uint8_t*)bytes)[0]==0);return 0;}
static void hint(struct wg_session *s,unsigned i,struct peer *p)
{
    uint8_t bytes[32]={0};bytes[0]=(uint8_t)i;
    struct wg_message m={.op=WG_HAVE,.id={.type=s->type}};
    assert(!identify(NULL,s->type,bytes,sizeof bytes,m.id.hash));
    assert(!wg_receive(s,&m,1000,emit,complete,p));
}
int main(void)
{
    struct wg_pool pool;struct wg_session source,alternative,operator,route;
    struct state state={0};struct peer a={0},b={0},op={0},r={0};
    struct wg_config cfg={.identify=identify,.objects=128,.pending=64,.bytes=32768,
        .downloads=6,.want_object=want,.context=&state};
    assert(!wg_init(&pool,&cfg));
    assert(!wg_open(&pool,&source,2) && !wg_open(&pool,&alternative,2));
    assert(!wg_open(&pool,&operator,3) && !wg_open(&pool,&route,1));
    for(unsigned i=0;i<64;i++)hint(&source,i,&a);
    assert(pool.pending_count==64 && !a.wants);state.demand=true;state.demand_calls=0;
    for(unsigned i=0;i<2500;i++){
        assert(!wg_poll(&operator,1001,emit,&op));
        assert(!wg_poll(&alternative,1001,emit,&b));
    }
    assert(!state.demand_calls && !op.wants && !b.wants);
    /* Four per owner, even with six available node-wide slots. */
    assert(!wg_poll(&source,1002,emit,&a) && a.wants==4);
    for(unsigned i=4;i<8;i++)hint(&alternative,i,&b);
    assert(b.wants==2); /* Both owners together use the six global slots. */
    uint8_t bytes[32]={0};struct wg_message data={.id=a.first.id,.op=WG_DATA,
        .request=a.first.request,.data=bytes,.size=32,.total=32};
    assert(!wg_receive(&source,&data,1003,emit,complete,&a));
    hint(&route,0,&r);assert(r.wants==1);
    assert(!wg_poll(&alternative,1004,emit,&b) && b.wants==2);
    wg_close(&source);wg_close(&alternative);wg_close(&operator);wg_close(&route);wg_deinit(&pool);
    puts("64 shared hints: unrelated sessions skip admission; four per-owner and six global downloads preserved");
}
