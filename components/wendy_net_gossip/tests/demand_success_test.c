/* Positive scheduler fixture: quiet service hints, route progress, local
 * demand, and completion of an already admitted transfer after demand ends. */
#include "wendy_net_gossip.h"
#include "test_sha256.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
struct driver {
    struct wg_pool *pool;
    uint64_t demand_until,now;
    unsigned emitted,completed;
    struct wg_message last;
};
static bool want(void *context,const struct wg_id *id,uint64_t now)
{
    struct driver *d=context;return id->type==1 || now<d->demand_until;
}
static int emit(void *context,const struct wg_message *m)
{
    struct driver *d=context;d->last=*m;d->emitted++;return 0;
}
static int complete(void *context,const struct wg_id *id,const void *bytes,size_t size)
{
    struct driver *d=context;struct wg_id accepted;
    /* Fixture bytes stand in for an adapter's independently verified body. */
    assert(!wg_offer(d->pool,id->type,bytes,size,d->now+60000,d->now,&accepted));
    assert(!memcmp(accepted.hash,id->hash,32));d->completed++;return 0;
}
static struct wg_message hint(uint8_t type,const char *body)
{
    struct wg_message m={.op=WG_HAVE,.id={.type=type}};
    assert(!identify(NULL,type,body,strlen(body),m.id.hash));return m;
}
static void finish(struct wg_session *s,struct driver *d,const char *body,uint64_t now)
{
    assert(d->last.op==WG_WANT);
    struct wg_message m=d->last;m.op=WG_DATA;m.data=(const uint8_t *)body;
    m.size=m.total=(uint32_t)strlen(body);m.offset=0;d->now=now;
    assert(!wg_receive(s,&m,now,emit,complete,d));
}
int main(void)
{
    struct wg_pool pool={0};struct driver d={.pool=&pool};
    struct wg_config config={.identify=identify,.context=&d,.objects=16,
        .pending=8,.route_pending_reserve=2,.bytes=8192,.downloads=1,.want_object=want};
    assert(!wg_init(&pool,&config));
    struct wg_session service={0},route={0};
    assert(!wg_open(&pool,&service,2) && !wg_open(&pool,&route,1));
    const char *services[]={"service0","service1","service2","service3","service4","service5"};
    size_t idle=wg_memory(&pool);
    for(unsigned i=0;i<6;i++){
        struct wg_message m=hint(2,services[i]);
        assert(!wg_receive(&service,&m,100,emit,complete,&d));
    }
    assert(pool.pending_count==6 && !d.emitted && !pool.payload_bytes);
    size_t quiet=wg_memory(&pool);
    struct wg_message excess=hint(2,"another service");
    assert(wg_receive(&service,&excess,100,emit,complete,&d)==1);
    assert(pool.pending_count==6 && wg_memory(&pool)==quiet);
    struct wg_message first_route=hint(1,"route0"),second_route=hint(1,"route1"),third_route=hint(1,"route2");
    assert(!wg_receive(&route,&first_route,101,emit,complete,&d));
    assert(d.emitted==1 && d.last.op==WG_WANT && d.last.id.type==1);
    assert(!wg_receive(&route,&second_route,101,emit,complete,&d));
    assert(pool.pending_count==8 && d.emitted==1);
    /* A further route announcement reclaims an idle service hint, rather
     * than waiting for local browsing or a later reconciliation timer. */
    assert(!wg_receive(&route,&third_route,101,emit,complete,&d));
    assert(pool.pending_count==8 && d.emitted==1);
    finish(&route,&d,"route0",102);
    assert(!wg_poll(&route,103,emit,&d));
    assert(d.last.op==WG_WANT && !memcmp(d.last.id.hash,second_route.id.hash,32));
    finish(&route,&d,"route1",104);
    assert(!wg_poll(&route,105,emit,&d));
    assert(d.last.op==WG_WANT && !memcmp(d.last.id.hash,third_route.id.hash,32));
    finish(&route,&d,"route2",106);
    assert(d.completed==3 && pool.pending_count==5);
    unsigned before=d.emitted;
    assert(!wg_poll(&service,107,emit,&d) && d.emitted==before);
    d.demand_until=15108;
    assert(!wg_poll(&service,108,emit,&d));
    assert(d.emitted==before+1 && d.last.op==WG_WANT && d.last.id.type==2);
    /* The admission window ends while this body is already in flight. */
    finish(&service,&d,services[1],15109);
    before=d.emitted;
    assert(!wg_poll(&service,15110,emit,&d) && d.emitted==before);
    assert(d.completed==4 && pool.pending_count==4);
    printf("Demand-only scheduler: six quiet hints=%zu bytes above idle, route reserve2/8, in-flight completion preserved\n",quiet-idle);
    wg_close(&service);wg_close(&route);wg_deinit(&pool);return 0;
}
