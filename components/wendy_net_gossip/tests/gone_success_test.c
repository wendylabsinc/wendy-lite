/* Normal proactive availability withdrawal and immediate supplier handover. */
#include "wendy_net_gossip.h"
#include "test_sha256.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
struct observed {unsigned wants;uint64_t request;};
static int emit(void *ctx,const struct wg_message *m)
{struct observed *o=ctx;if(m->op==WG_WANT){o->wants++;o->request=m->request;}return 0;}
static int complete(void *ctx,const struct wg_id *id,const void *bytes,size_t n)
{(void)ctx;(void)id;(void)bytes;(void)n;return 0;}
int main(void)
{
    struct wg_pool p;struct wg_session first,other;
    struct wg_config config={.identify=identify,.objects=4,.pending=4,.bytes=8192};
    assert(!wg_init(&p,&config) && !wg_open(&p,&first,2) && !wg_open(&p,&other,2));
    struct wg_message have={.op=WG_HAVE,.id.type=2};memset(have.id.hash,7,32);
    struct observed a={0},b={0};
    assert(!wg_receive(&first,&have,1000,emit,complete,&a) && a.wants==1);
    assert(!wg_receive(&other,&have,1001,emit,complete,&b) && !b.wants);
    struct wg_message gone={.op=WG_GONE,.id=have.id};
    assert(!wg_validate(&gone));
    assert(!wg_receive(&first,&gone,1002,emit,complete,&a));
    assert(!wg_poll(&other,1003,emit,&b) && b.wants==1);
    assert(!wg_poll(&first,1004,emit,&a) && a.wants==1);
    /* No idle timeout elapsed: an alternate supplier can already send. */
    assert(!wg_receive(&other,&gone,1005,emit,complete,&b) && !p.pending_count);
    wg_close(&first);wg_close(&other);wg_deinit(&p);
    puts("Proactive GONE immediately releases a supplier claim and stale HAVE");
}
