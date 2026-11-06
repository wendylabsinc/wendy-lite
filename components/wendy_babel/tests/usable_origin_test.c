/* Exact candidate readiness and standard refresh request boundaries. */
#include "wendy_babel.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
static bool permit = true, fail_alloc;
static unsigned allocations, releases, requests;
static bool allow(void *ctx, uint64_t router, const struct wb_prefix *p, uint16_t seq)
{ (void)ctx; (void)router; (void)p; (void)seq; return permit; }
static void *allocate(void *ctx, size_t bytes)
{ (void)ctx; if (fail_alloc) return NULL; allocations++; return malloc(bytes); }
static void release(void *ctx, void *p)
{ (void)ctx; releases++; free(p); }
static void receive(void *ctx, const struct wb_message *m)
{ const struct wb_prefix *p=ctx; assert(m->type==WB_REQUEST && !m->wildcard && wb_prefix_equal(&m->prefix,p)); requests++; }
int main(void)
{
    struct wb_prefix p={.family=6,.bits=128,.bytes={0xfd,0x45,0xb8,0x91,0x56,0x7f}};
    p.bytes[15]=7;
    struct wb_link_state links[2]={
        {.config={.id=1,.cost=128,.max_packet=WB_PACKET_MAX,.peer={0xfe,0x80}},.tx=128,.ihu_expires=5000,.hello_expires={5000,0}},
        {.config={.id=2,.cost=8192,.max_packet=WB_PACKET_MAX,.peer={0xfe,0x80}},.tx=8192,.ihu_expires=5000,.hello_expires={5000,0}}};
    struct wb_candidate candidates[2]={
        {.used=true,.expires=5000,.advertised=0,.route={.prefix=p,.router=42,.seqno=7,.link=1}},
        {.used=true,.expires=5000,.advertised=100,.route={.prefix=p,.router=42,.seqno=8,.link=2}}};
    struct wb_source source={.used=true,.prefix=p,.router=42,.seqno=7,.metric=128,.expires=10000};
    struct wb_route installed={.prefix=p,.router=42,.seqno=7,.link=1,.metric=128};
    struct wb_engine e={.config={.allow=allow,.allocate=allocate,.deallocate=release},.ready=true,.now=1000,
        .links=links,.links_capacity=2,.candidates=candidates,.candidates_capacity=2,
        .sources=&source,.sources_capacity=1,.routes=&installed,.routes_capacity=1,.route_count=1};
    struct wb_engine before=e;
    assert(wb_lookup(&e,&p)->seqno==7);
    assert(wb_has_usable_origin(&e,1000,&p,42,8)); /* Higher-metric, nonselected. */
    assert(!memcmp(&before,&e,sizeof e) && !allocations && !requests);
    permit=false; assert(!wb_has_usable_origin(&e,1000,&p,42,8)); permit=true;
    source.seqno=8; source.metric=100; assert(!wb_has_usable_origin(&e,1000,&p,42,8));
    source.metric=101; assert(wb_has_usable_origin(&e,1000,&p,42,8));
    source.seqno=9; assert(!wb_has_usable_origin(&e,1000,&p,42,8));
    source.expires=1000; assert(wb_has_usable_origin(&e,1000,&p,42,8)); source= (struct wb_source){.used=true,.prefix=p,.router=42,.seqno=7,.metric=128,.expires=10000};
    candidates[1].advertised=WB_INFINITY; assert(!wb_has_usable_origin(&e,1000,&p,42,8)); candidates[1].advertised=100;
    candidates[1].expires=1000; assert(!wb_has_usable_origin(&e,1000,&p,42,8)); candidates[1].expires=5000;
    candidates[1].used=false; assert(!wb_has_usable_origin(&e,1000,&p,42,8)); candidates[1].used=true;
    links[1].ihu_expires=1500; assert(!wb_has_usable_origin(&e,2000,&p,42,8)); links[1].ihu_expires=5000;
    links[1].hello_expires[0]=1500; assert(!wb_has_usable_origin(&e,2000,&p,42,8)); links[1].hello_expires[0]=5000;
    links[1].ihu_expires=1000; assert(!wb_has_usable_origin(&e,1000,&p,42,8)); links[1].ihu_expires=5000;
    links[1].hello_expires[0]=1000; assert(!wb_has_usable_origin(&e,1000,&p,42,8)); links[1].hello_expires[0]=5000;
    links[1].tx=WB_INFINITY; assert(!wb_has_usable_origin(&e,1000,&p,42,8)); links[1].tx=8192;
    links[1].config.id=0; assert(!wb_has_usable_origin(&e,1000,&p,42,8)); links[1].config.id=2;
    candidates[1].advertised=60000; assert(!wb_has_usable_origin(&e,1000,&p,42,8)); candidates[1].advertised=100;
    assert(!wb_has_usable_origin(&e,999,&p,42,8));
    assert(!wb_has_usable_origin(&e,1000,&p,43,8));
    assert(!wb_has_usable_origin(&e,1000,&p,42,9));
    e.pending=1; assert(!wb_has_usable_origin(&e,1000,&p,42,8)); assert(wb_request_prefix(&e,&p)==WB_BUSY); e.pending=0;
    links[0].config.id=links[1].config.id=0;
    assert(wb_request_prefix(&e,&p)==WB_BUSY && !e.message_count && !allocations);
    links[0].config.id=1;links[1].config.id=2;
    fail_alloc=true; assert(wb_request_prefix(&e,&p)==WB_LIMIT && !e.message_count && !e.messages); fail_alloc=false;
    uint64_t now=e.now, revision=e.revision, trigger=e.trigger_at;
    assert(!wb_request_prefix(&e,&p) && e.message_count==2);
    assert(e.now==now && e.revision==revision && e.trigger_at==trigger && e.route_count==1 && installed.seqno==7);
    uint8_t packet[WB_PACKET_MAX]; uint64_t link;
    for (;;) {
        int n=wb_next_packet(&e,&link,packet,sizeof packet); assert(n>=0); if(!n)break;
        assert(link==1 || link==2);
        assert(!wb_decode(packet,(size_t)n,links[link-1].config.peer,receive,&p));
    }
    assert(requests==2 && allocations==releases); /* Consumed output collects its storage. */
    e.links=NULL;e.candidates=NULL;e.sources=NULL;e.routes=NULL;
    e.links_capacity=e.candidates_capacity=e.sources_capacity=e.routes_capacity=0;
    wb_deinit(&e);
    assert(allocations==releases);
    puts("Usable current candidates and bounded standard prefix refresh PASS");
    return 0;
}
