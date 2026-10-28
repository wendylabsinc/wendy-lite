/* Ordinary large-mesh endpoint load. Outer admission has authenticated the
 * sole carrier; this tests local/default routing and bounded Babel state. */
#include "wendy_net_router.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
struct observed {unsigned publications,packets;uint8_t own[16];};
static int publish(void *context,const struct wn_origin *origin,int64_t wall,int64_t now)
{struct observed *o=context;(void)wall;(void)now;assert(origin->router_id==444);o->publications++;return 0;}
static void inspect(void *context,const struct wb_message *m)
{struct observed *o=context;if(m->type==WB_UPDATE)assert(m->prefix.bits==128 && !memcmp(m->prefix.bytes,o->own,16));}
static int send_packet(void *context,uint64_t link,const void *bytes,size_t size)
{struct observed *o=context;uint8_t from[16]={0xfe,0x80};assert(link);assert(!wb_decode(bytes,size,from,inspect,o));o->packets++;return 0;}
static int receive(struct wnr_core *core,uint64_t link,const struct wb_message *m,int64_t wall,int64_t now)
{
 uint8_t packet[256]={42,2};size_t size=wb_encode(m,packet+4,sizeof packet-4);assert(size && size<252);
 wn_put16(packet+2,(uint16_t)size);return wnr_receive(core,link,packet,size+4,wall,now);
}
int main(void)
{
 const char *tenant="2558fd76-afc7-466e-9613-6b715296a526";
 const char *self="00000000-0000-4000-8000-0000000000ff";
 struct observed observed={0};uint8_t uuid[16];assert(!wn_uuid_parse(self,uuid));wn_address(uuid,observed.own);
 struct wnr_core core={0};struct wnr_config config={.tenant=tenant,.device=self,.router=444,
  .non_transit=true,.endpoint_gateway=true,.context=&observed,.publish=publish,.send=send_packet};
 const int64_t wall=1800000000000,epoch=1000000;
 assert(!wnr_init(&core,&config,epoch,NULL,0) && !wnr_start(&core,wall,epoch));
 uint64_t link=0;assert(!wnr_attach(&core,"00000000-0000-4000-8000-0000000000fe",8192,wall+1,epoch+1000,&link));
 assert(link && observed.publications && core.babel.config.local_only);
 uint64_t extra=0;assert(wnr_attach(&core,"00000000-0000-4000-8000-0000000000fd",8192,wall+1,epoch+1000,&extra)==WB_LIMIT && !extra);
 struct wb_message hello={.type=WB_HELLO,.interval=400,.seqno=1};
 assert(!receive(&core,link,&hello,wall+2,epoch+2000));
 size_t baseline=wnr_memory(&core);
 for(unsigned i=1;i<=100;i++){
  struct wb_message update={.type=WB_UPDATE,.router=1000+i,.seqno=1,.interval=1600,.metric=0,
   .prefix={.bits=128,.family=6},.address_family=6,.address={0xfe,0x80}};
  uint8_t remote[16]={0};remote[6]=0x40;remote[8]=0x80;remote[14]=(uint8_t)(i>>8);remote[15]=(uint8_t)i;
  wn_address(remote,update.prefix.bytes);update.address[15]=1;
  assert(!receive(&core,link,&update,wall+2+i,epoch+(int64_t)(2+i)*1000));
  assert(!core.stopped && core.directory.count==0 && core.directory.key_count==0);
  assert(core.babel.route_count==1 && !core.babel.candidates_capacity);
  assert(wnr_memory(&core)==baseline);
  if(i==10 || i==40 || i==100)printf("origins=%u retained=%zu routes=%zu foreign_keys=%u\n",i,baseline,core.babel.route_count,core.directory.key_count);
 }
 /* A normal inbound connection can reach local delivery after its origin's
  * routing update was ignored; the TLS endpoint then verifies its certificate. */
 uint8_t remote_uuid[16]={0};remote_uuid[6]=0x40;remote_uuid[8]=0x80;remote_uuid[15]=3;
 uint8_t packet[60]={0x60};wn_put16(packet+4,20);packet[6]=6;packet[7]=64;
 wn_address(remote_uuid,packet+8);memcpy(packet+24,observed.own,16);
 wn_put16(packet+40,42000);wn_put16(packet+42,5054);packet[52]=0x50;packet[53]=2;
 uint64_t outgoing=999;assert(!wnr_packet(&core,link,packet,sizeof packet,epoch+110000,&outgoing) && !outgoing);
 uint8_t address[16];memcpy(address,packet+8,16);memcpy(packet+8,observed.own,16);memcpy(packet+24,address,16);
 assert(wnr_packet(&core,0,packet,sizeof packet,epoch+110000,&outgoing)==1 && outgoing==link && packet[7]==64);
 assert(!wnr_detach(&core,link,wall+111,epoch+111000));
 struct wb_route absent;assert(!wnr_lookup(&core,address,epoch+112000,&absent));
 wnr_deinit(&core);puts("Endpoint default gateway: constant routing memory through100 announced origins; incoming/local reply path remains usable");
}
