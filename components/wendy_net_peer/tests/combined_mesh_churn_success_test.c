/* Positive component integration: actual Go signatures, native router and
 * bounded caches. One admitted carrier relays 80 origins; this is a host
 * model, not a radio or complete firmware heap measurement. */
#include "wendy_net_router.h"
#include "wendy_net_control.h"
#include "wendy_net_gossip.h"
#include "catalog_internal.h"
#include "wendy_net_alloc.h"
#include "wendy_pki_crypto.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char tenant[]="11111111-1111-4111-8111-111111111111";
static const char self[]="99999999-9999-4999-8999-999999999999";
static const int64_t wall=INT64_C(1800000000000),epoch=INT64_C(1000000);
struct model {
    struct wnr_core *core;
    struct wnsc_node *catalog;
    struct wg_pool pool;
    struct wg_id artifacts[81];
    bool cached[81],small;
    uint64_t link;
    unsigned packets,verified;
};
static void uuid_text(unsigned id,char text[37])
{assert(snprintf(text,37,"00000000-0000-4000-8000-%012x",id)==36);}
static void *read_file(const char *directory,unsigned id,unsigned revision,size_t *size)
{
 char path[2048];int n=revision ? snprintf(path,sizeof path,"%s/origin-%03u-r%u.cbor",directory,id,revision):
   snprintf(path,sizeof path,"%s/origin-%03u-spki.der",directory,id);
 assert(n>0 && (size_t)n<sizeof path);FILE *f=fopen(path,"rb");assert(f);
 assert(!fseek(f,0,SEEK_END));long count=ftell(f);assert(count>0 && count<32768);rewind(f);
 void *bytes=wendy_net_malloc((size_t)count);assert(bytes);
 assert(fread(bytes,1,(size_t)count,f)==(size_t)count);fclose(f);*size=(size_t)count;return bytes;
}
static int publish(void *context,const struct wn_origin *origin,int64_t issued,int64_t now)
{(void)context;(void)origin;(void)issued;(void)now;return 0;}
static int send_packet(void *context,uint64_t link,const void *bytes,size_t size)
{struct model *m=context;assert(link && bytes && size);m->packets++;return 0;}
static uint64_t next_hop(void *context,const uint8_t device[16],uint64_t exclude)
{
 struct model *m=context;uint8_t address[16];struct wb_route route;wn_address(device,address);
 return wnr_lookup(m->core,address,m->core->now_us,&route) && route.link!=exclude ? route.link:0;
}
static struct wnd_entry *directory_entry(struct model *m,const uint8_t device[16])
{for(struct wnd_entry *e=m->core->directory.entries;e;e=e->next)if(!memcmp(e->device,device,16))return e;return NULL;}
static struct wne_entry *endpoint_entry(struct model *m,const uint8_t device[16])
{for(struct wne_entry *e=m->core->endpoints.entries;e;e=e->next)if(!memcmp(e->device,device,16))return e;return NULL;}
static void babel_update(struct model *m,unsigned id,int64_t at)
{
 uint8_t data[256]={42,2},device[16];char uuid[37];uuid_text(id,uuid);assert(!wn_uuid_parse(uuid,device));
 struct wb_message hello={.type=WB_HELLO,.interval=400,.seqno=(uint16_t)(1+at%60000)},
  ihu={.type=WB_IHU,.interval=800,.metric=128},
  update={.type=WB_UPDATE,.router=1000+id,.seqno=7,.interval=1600,.metric=0,
    .prefix={.bits=128,.family=6},.address_family=6,.address={0xfe,0x80}};
 update.address[15]=1;wn_address(device,update.prefix.bytes);
 size_t size=4;size+=wb_encode(&hello,data+size,sizeof data-size);
 size+=wb_encode(&ihu,data+size,sizeof data-size);size+=wb_encode(&update,data+size,sizeof data-size);
 wn_put16(data+2,(uint16_t)(size-4));
 assert(!wnr_receive(m->core,m->link,data,size,wall+at,epoch+at*1000));
}
static void accept(struct model *m,const char *fixtures,unsigned id,unsigned revision)
{
 char uuid[37];uuid_text(id,uuid);uint8_t device[16];assert(!wn_uuid_parse(uuid,device));
 int64_t at=(int64_t)(revision-1)*10000+id;
 struct wendy_pki_mesh_peer *peer=wendy_net_calloc(1,sizeof *peer);assert(peer);
 strcpy(peer->device,uuid);peer->expires=1800003600;
 size_t size;void *spki=read_file(fixtures,id,0,&size);assert(size<=sizeof peer->spki);
 memcpy(peer->spki,spki,size);peer->spki_size=size;wendy_net_free(spki);
 /* The enclosing identity adapter has authenticated these fixture SPKIs.
  * Every manifest below still verifies its actual independent signature. */
 assert(!wnr_identity(m->core,peer,wall+at,epoch+at*1000));wendy_net_free(peer);
 void *wire=read_file(fixtures,id,revision,&size);
 assert(!wnr_manifest(m->core,wire,size,wall+at,epoch+at*1000));m->verified++;
 struct wnd_entry *entry=directory_entry(m,device);assert(entry && entry->revision==revision);
 if(m->small)assert(!wne_update(&m->core->endpoints,&entry->manifest,entry->body_hash,entry->deadline_us ? entry->deadline_us:epoch+(at+900000)*1000,epoch+at*1000));
 struct wn_doc *doc=wendy_net_malloc(sizeof *doc);assert(doc);
 assert(!wn_doc_parse_array_view(doc,wire,size,WN_MANIFEST_WIRE_MAX,"services"));
 unsigned body=(unsigned)wn_doc_member(doc,0,"body");
 assert(!wnsc_manifest_services(m->catalog,doc,body,device,entry->revision,
  entry->manifest.issued,entry->manifest.expires,entry->manifest.withdraw));wendy_net_free(doc);
 for(struct wns_entry *s=m->catalog->records.entries;s;s=s->next)if(!memcmp(s->device,device,16)){
  assert(s->generation==revision && s->issued==entry->manifest.issued && s->expires==entry->manifest.expires);
  if(revision==2)assert(strcmp(wns_entry_service(s),"temperature-02"));
 }
 if(!m->small){
  if(m->cached[id])wg_forget(&m->pool,&m->artifacts[id]);
  assert(!wg_offer(&m->pool,1,wire,size,(uint64_t)(epoch/1000+entry->manifest.expires-wall),
   (uint64_t)(epoch/1000+at),&m->artifacts[id]));m->cached[id]=true;
 }
 wendy_net_free(wire);
 if(revision!=3)babel_update(m,id,at);
 assert(!m->core->stopped && m->core->directory.key_count<=(m->small ? 8u:128u));
 assert(m->catalog->records.count<=(m->small ? 64u:512u));
 assert(m->catalog->records.bytes<=m->catalog->records.byte_limit);
 if(m->small){assert(m->core->directory.count<=8 && m->core->endpoints.count<=64 && m->core->babel.route_count==1);assert(!m->pool.object_count && !m->pool.payload_bytes);}
}
static void incoming_after_eviction(struct model *m)
{
 uint8_t device[16],packet[60]={0x60};char uuid[37];uuid_text(1,uuid);assert(!wn_uuid_parse(uuid,device));
 assert(!directory_entry(m,device) && !endpoint_entry(m,device));
 assert(!wns_store_find(&m->catalog->records,device,"sh.example.sensors","temperature-00"));
 wn_put16(packet+4,20);packet[6]=6;packet[7]=64;wn_address(device,packet+8);
 memcpy(packet+24,m->core->directory.self_address,16);wn_put16(packet+40,42000);wn_put16(packet+42,5054);packet[52]=0x50;packet[53]=2;
 uint64_t outgoing=999;assert(!wnr_packet(m->core,m->link,packet,sizeof packet,epoch+100000,&outgoing) && !outgoing);
 uint8_t address[16];memcpy(address,packet+8,16);memcpy(packet+8,packet+24,16);memcpy(packet+24,address,16);
 assert(wnr_packet(m->core,0,packet,sizeof packet,epoch+100000,&outgoing)==1 && outgoing==m->link);
}
static void run(const char *fixtures,bool small)
{
 assert(wendy_net_memory_open(wendy_net_runtime_memory_ledger(),small ? 160*1024:2*1024*1024,!small));
 struct model m={.small=small};m.core=wendy_net_calloc(1,sizeof *m.core);assert(m.core);
 struct wnr_config cfg={.tenant=tenant,.device=self,.router=999,.non_transit=small,.endpoint_gateway=small,.context=&m,.publish=publish,.send=send_packet};
 assert(!wnr_init(m.core,&cfg,epoch,NULL,0) && !wnr_start(m.core,wall,epoch));
 if(small)assert(!wnd_key_limit(&m.core->directory,8));
 assert(!wnr_attach(m.core,"00000000-0000-4000-8000-0000000000fe",128,wall,epoch,&m.link));
 struct wnsc_config sc={.tenant=tenant,.device=self,.catalog_bytes=small ? 32768:512*1024,.catalog_records=small ? 64:512,.context=&m,.next_hop=next_hop};
 assert(!wnsc_open(&m.catalog,&sc));
 struct wg_config gc={.objects=1024,.pending=64,.bytes=512*1024,.fifo=true,.identify=wn_gossip_identify};assert(!wg_init(&m.pool,&gc));
 for(unsigned id=1;id<=80;id++)accept(&m,fixtures,id,1);
 if(small)incoming_after_eviction(&m);
 else{assert(m.pool.object_count==80 && m.core->babel.route_count==81 && m.catalog->records.count==240);}
 uint8_t retained[16];char uuid[37];uuid_text(64,uuid);assert(!wn_uuid_parse(uuid,retained));
 struct wne_entry *old=endpoint_entry(&m,retained);
 for(unsigned id=57;id<=80;id++)accept(&m,fixtures,id,2);
 if(small)assert(endpoint_entry(&m,retained)==old && old && old->app_port==44022);
 for(unsigned id=73;id<=80;id++)accept(&m,fixtures,id,3);
 if(small){uint16_t port;for(unsigned id=73;id<=80;id++){uuid_text(id,uuid);assert(!wn_uuid_parse(uuid,retained));assert(!wne_endpoint(&m.core->endpoints,retained,false,epoch+21000000,&port));}}
 for(unsigned id=73;id<=80;id++)accept(&m,fixtures,id,4);
 /* The public outgoing API still uses origin64's compact capability after its
  * signing key has been evicted on C6. C5 uses its full verified directory. */
 uuid_text(64,uuid);assert(!wn_uuid_parse(uuid,retained));uint16_t port;
 assert(wnr_app_endpoint(m.core,retained,m.core->now_us,&port) && port==44022);
 assert(next_hop(&m,retained,0)==m.link);
 wendy_net_memory_snapshot_t memory;wendy_net_runtime_memory_snapshot(&memory);
 printf("%s: verified=%u origins=80 keys=%u endpoints=%u service_rows=%zu service_bytes=%zu full_manifests=%zu payload=%zu routes=%zu charged_current=%zu charged_peak=%zu refusals=%llu\n",
  small ? "C6 policy":"C5 PSRAM policy",m.verified,m.core->directory.key_count,m.core->endpoints.count,m.catalog->records.count,m.catalog->records.bytes,m.pool.object_count,m.pool.payload_bytes,m.core->babel.route_count,memory.current_bytes,memory.high_water_bytes,(unsigned long long)memory.failed_admissions);
 const int64_t expired_at=915000;wnsc_prune(m.catalog,wall+expired_at);wne_reap(&m.core->endpoints,epoch+expired_at*1000);wg_prune(&m.pool,(uint64_t)(epoch/1000+expired_at));
 assert(m.catalog->records.count==24);
 if(small)assert(m.core->endpoints.count==8 && !m.pool.object_count);
 else assert(m.pool.object_count==8);
 printf("%s: after old-lease expiry service_rows=%zu endpoints=%u full_manifests=%zu\n",small ? "C6 policy":"C5 PSRAM policy",m.catalog->records.count,m.core->endpoints.count,m.pool.object_count);
 wnsc_close(m.catalog);wg_deinit(&m.pool);wnr_deinit(m.core);wendy_net_free(m.core);
 wendy_net_runtime_memory_close();assert(wendy_net_runtime_memory_drained());
}
int main(int argc,char **argv)
{assert(argc==2 && !wendy_pki_crypto_init());run(argv[1],false);run(argv[1],true);return 0;}
