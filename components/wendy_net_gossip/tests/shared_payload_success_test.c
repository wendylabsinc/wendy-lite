/* Normal shared payload lifetime across multi-chunk delivery and replacement. */
#include "wendy_net_gossip.h"
#include "test_sha256.h"
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct blob {unsigned refs;unsigned char bytes[1536];};
static unsigned released,frames;
static const unsigned char *expected;
static struct blob *owner(const void *p)
{return (struct blob *)((unsigned char *)p - offsetof(struct blob,bytes));}
static void retain(const void *p){owner(p)->refs++;}
static void release(const void *p)
{struct blob *b=owner(p);assert(b->refs);if(!--b->refs){released++;free(b);}}
static struct blob *make(unsigned seed)
{struct blob *b=malloc(sizeof *b);assert(b);b->refs=1;for(unsigned i=0;i<sizeof b->bytes;i++)b->bytes[i]=(unsigned char)(seed+i);return b;}
static int emit(void *ctx,const struct wg_message *m)
{
    (void)ctx;
    if(m->op==WG_DATA){assert(m->data==expected+m->offset);assert(!memcmp(m->data,expected+m->offset,m->size));frames++;}
    return 0;
}
static int complete(void *ctx,const struct wg_id *id,const void *bytes,size_t n)
{(void)ctx;(void)id;(void)bytes;(void)n;return 0;}
int main(void)
{
    struct wg_config cfg={.identify=identify,.objects=4,.pending=4,.bytes=8192};
    struct wg_pool p;struct wg_session s;struct wg_id id;
    assert(!wg_init(&p,&cfg) && !wg_open(&p,&s,2));
    struct blob *b=make(1);expected=b->bytes;
    assert(!wg_offer_shared(&p,2,b->bytes,sizeof b->bytes,61000,1000,&id,retain,release));
    assert(b->refs==2);
    assert(!wg_offer_shared(&p,2,b->bytes,sizeof b->bytes,61000,1001,&id,retain,release));
    assert(b->refs==2); /* Re-observation has no additional ownership. */
    struct wg_message want={.id=id,.op=WG_WANT,.request=1};
    assert(!wg_receive(&s,&want,1002,emit,complete,NULL));
    assert(!wg_poll(&s,1003,emit,NULL) && frames==1);
    release(b->bytes); /* The registry replaces/releases its version mid-send. */
    assert(!released);
    assert(!wg_poll(&s,1004,emit,NULL) && frames==2);
    wg_forget(&p,&id);assert(released==1 && !p.object_count);
    b=make(2);expected=b->bytes;
    assert(!wg_offer_shared(&p,2,b->bytes,sizeof b->bytes,61000,1010,&id,retain,release));
    want.id=id;want.request=2;
    assert(!wg_receive(&s,&want,1011,emit,complete,NULL));
    release(b->bytes);wg_forget(&p,&id);
    assert(released==1); /* Active transfer still owns the pool object. */
    assert(!wg_poll(&s,1012,emit,NULL));
    wg_prune(&p,1013);assert(released==2 && !p.object_count);
    b=make(3);
    assert(!wg_offer_shared(&p,2,b->bytes,sizeof b->bytes,61000,1020,&id,retain,release));
    release(b->bytes);wg_close(&s);wg_deinit(&p);assert(released==3);
    puts("Shared payloads survive normal transfer/replacement and release exactly once");
    return 0;
}
