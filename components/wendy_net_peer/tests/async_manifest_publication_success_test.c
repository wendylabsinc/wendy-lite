/* Ordinary large-mesh endpoint load. Outer admission has authenticated the
 * sole carrier; this tests local/default routing and bounded Babel state. */
#include "wendy_net_router.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
struct observed {unsigned publications,packets;uint8_t own[16];};
static void inspect(void *context,const struct wb_message *m)
{struct observed *o=context;if(m->type==WB_UPDATE)assert(m->prefix.bits==128 && !memcmp(m->prefix.bytes,o->own,16));}
static int send_packet(void *context,uint64_t link,const void *bytes,size_t size)
{struct observed *o=context;uint8_t from[16]={0xfe,0x80};assert(link);assert(!wb_decode(bytes,size,from,inspect,o));o->packets++;return 0;}
static int receive(struct wnr_core *core,uint64_t link,const struct wb_message *m,int64_t wall,int64_t now)
{
 uint8_t packet[256]={42,2};size_t size=wb_encode(m,packet+4,sizeof packet-4);assert(size && size<252);
 wn_put16(packet+2,(uint16_t)size);return wnr_receive(core,link,packet,size+4,wall,now);
}

struct asynchronous {struct observed observed;struct wnr_core *core;unsigned calls,remaining;bool delay,loan;};
static int asynchronous_publish(void *context,const struct wn_origin *origin,int64_t wall,int64_t now)
{
 struct asynchronous *a=context;(void)origin;(void)wall;(void)now;a->calls++;
 if(!a->delay)return 0;
 if(!a->loan){a->loan=true;a->remaining=2;a->core->publication_dirty=false;}
 if(a->remaining){a->remaining--;return 1;}
 a->loan=false;return 0;
}
int main(void)
{
 struct asynchronous a={0};struct wnr_core core={0};a.core=&core;
 const char *tenant="2558fd76-afc7-466e-9613-6b715296a526",*self="00000000-0000-4000-8000-0000000000ff";
 uint8_t uuid[16];assert(!wn_uuid_parse(self,uuid));wn_address(uuid,a.observed.own);
 struct wnr_config config={.tenant=tenant,.device=self,.router=444,.non_transit=true,.endpoint_gateway=true,
  .context=&a,.publish=asynchronous_publish,.send=send_packet};
 const int64_t wall=1800000000000,epoch=1000000;uint64_t link=0;
 assert(!wnr_init(&core,&config,epoch,NULL,0) && !wnr_start(&core,wall,epoch));
 assert(!wnr_attach(&core,"00000000-0000-4000-8000-0000000000fe",8192,wall+1,epoch+1000,&link));
 struct wb_message hello={.type=WB_HELLO,.interval=400,.seqno=1};assert(!receive(&core,link,&hello,wall+2,epoch+2000));
 assert(core.published && !core.publication_pending);
 unsigned before=a.calls;int64_t previous=core.published_us;a.delay=true;core.publication_dirty=true;
 assert(!wnr_tick(&core,wall+2000,epoch+2000000));
 assert(a.calls==before+1 && core.publication_pending && !core.publication_dirty && core.published_us==previous);
 /* The dirty flag was consumed by the immutable draft. No new edit is needed
  * to collect a delayed whole-call crypto completion on the next tick. */
 assert(!wnr_tick(&core,wall+2010,epoch+2010000));assert(a.calls==before+2 && core.publication_pending);
 core.publication_dirty=true; /* A later edit must survive this completion. */
 assert(!wnr_tick(&core,wall+2020,epoch+2020000));
 assert(a.calls==before+3 && !core.publication_pending && core.publication_dirty);
 assert(!wnr_tick(&core,wall+2030,epoch+2030000));assert(a.calls==before+3);
 assert(!wnr_tick(&core,wall+3020,epoch+3020000));assert(a.calls==before+4 && core.publication_pending);
 assert(!wnr_tick(&core,wall+3030,epoch+3030000));assert(!wnr_tick(&core,wall+3040,epoch+3040000));
 assert(a.calls==before+6 && !core.publication_pending && !core.publication_dirty);
 /* A sequence request just inside the gate may commit local state, but
  * its new Babel authorization cannot leave before the replacement proof. */
 a.delay=false;unsigned packets=a.observed.packets,signs=a.calls;
 uint16_t previous_seq=core.published_seqno;
 struct wb_message request={.type=WB_SEQ_REQUEST,.router=444,.seqno=(uint16_t)(core.babel.seqno+1),.hops=2,.prefix={.family=6,.bits=128}};
 memcpy(request.prefix.bytes,a.observed.own,16);
 assert(!receive(&core,link,&request,wall+3050,epoch+3050000));
 assert(core.babel.seqno!=previous_seq && core.published_seqno==previous_seq);
 assert(a.calls==signs && a.observed.packets==packets && wnr_busy(&core));
 assert(!wnr_tick(&core,wall+4040,epoch+4040000));
 assert(core.published_seqno==core.babel.seqno && a.calls==signs+1 && a.observed.packets>packets && !wnr_busy(&core));
 wnr_deinit(&core);puts("delayed manifest completion progresses without new edits; later edits survive and respect one second gate PASS");return 0;
}
