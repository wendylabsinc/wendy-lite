/* Actual directory/Babel/session transaction, including deferred verification. */
#include "wendy_net_gossip.h"
static const void *pressure_wire;
static int controlled_offer(struct wg_pool *p,uint8_t type,const void *bytes,size_t size,
                            uint64_t expires,uint64_t now,struct wg_id *id)
{ return pressure_wire==bytes?1:wg_offer(p,type,bytes,size,expires,now,id); }
#define wg_offer controlled_offer
#define main existing_shared_router_main
#include "router_node_success_test.c"
#undef main
#undef wg_offer
#include "wendy_pki_work.h"
#include <arpa/inet.h>
static unsigned handoff_revision=1;
static char last_body[768],last_principal[106],last_wire[1500];static size_t last_body_size,last_wire_size;
static bool publish_withdraw;static int64_t publication_offset_ms;
static int64_t publication_duration_ms=60000;
static void drop_frames(void) { while(head){struct frame*f=head;head=f->next;free(f);}tail=&head; }
static struct wnd_entry *handoff_claim(struct wnrs_node *node,const uint8_t a[16])
{for(struct wnd_entry*e=node->core.directory.entries;e;e=e->next)if(!memcmp(e->address,a,16))return e;return NULL;}
static void handoff_publish(struct endpoint *peer,uint16_t seq,uint16_t port,bool asynchronous)
{
 uint8_t uuid[16],signature[80];char body[768],principal[106],proof[1500];
 assert(!wn_uuid_parse(ids[peer->index],uuid));
 struct wn_origin origin={.router_id=peer->remote.config.router,.seqno=seq};
 int64_t wall=node_unix(peer->session->node)+publication_offset_ms;
 char services[160];struct wn_writer w={.data=(uint8_t *)services,.capacity=sizeof services,.maximum=sizeof services};
 wn_array(&w,1);wn_map(&w,6);
 wn_text(&w,"a");wn_text(&w,"app.test");wn_text(&w,"m");wn_text(&w,"default");
 wn_text(&w,"s");wn_text(&w,"telemetry");wn_text(&w,"t");wn_text(&w,"_sensorlink._tcp");
 wn_text(&w,"n");wn_text(&w,"Live");wn_text(&w,"p");wn_uint(&w,28000);
 int n=wn_manifest_services_write(uuid,&origin,++handoff_revision,wall,wall+publication_duration_ms,port,43022,
                                  NULL,false,services,w.size,body,sizeof body);
 assert(n>0&&wn_principal(tenant,ids[peer->index],principal)>0);
 if(publish_withdraw){assert((uint8_t)body[0]==0xad);body[0]=(char)0xae;
  struct wn_writer extra={.data=(uint8_t *)body+n,.capacity=sizeof body-(size_t)n,.maximum=sizeof body-(size_t)n};
  wn_key(&extra,"withdraw");wn_bool(&extra,true);int added=wn_finish(&extra);assert(added>0);n+=added;}
 size_t signed_size;
 assert(!wendy_pki_mesh_sign(NULL,principal,body,(size_t)n,signature,&signed_size));
 memcpy(last_body,body,(size_t)n);last_body_size=(size_t)n;strcpy(last_principal,principal);
 n=wn_manifest_wire_write(principal,body,(size_t)n,signature,signed_size,proof,sizeof proof);assert(n>0);
 memcpy(last_wire,proof,(size_t)n);last_wire_size=(size_t)n;
 if(!asynchronous){assert(!wnr_manifest(&peer->session->node->core,proof,(size_t)n,wall,clock_us));return;}
 struct wg_id id={.type=1};assert(!wn_gossip_identify(NULL,1,proof,(size_t)n,id.hash));
 int result=complete(peer->session,&id,proof,(size_t)n);unsigned deferred=0;
 while(result==WG_DEFER){assert(++deferred<8);(void)wendy_pki_work_poll();result=complete(peer->session,&id,proof,(size_t)n);}
 assert(!result&&deferred);
}
static void handoff_update(struct wnrs *from,const uint8_t a[16],uint64_t router,uint16_t seq,uint16_t metric)
{
 uint8_t packet[WB_PACKET_MAX]={42,2};
 struct wb_message m={.type=WB_UPDATE,.router=router,.seqno=seq,.metric=metric,.interval=400,.prefix={.family=6,.bits=128}};
 memcpy(m.prefix.bytes,a,16);size_t n=wb_encode(&m,packet+4,sizeof packet-4);assert(n);
 packet[2]=(uint8_t)(n>>8);packet[3]=(uint8_t)n;assert(!wnrs_routing(from,packet,n+4));
}
static void live_consumers(struct wnrs_node *node,struct endpoint *source,const uint8_t address[16],uint64_t expected_link)
{
 uint8_t uuid[16];assert(!wn_uuid_parse(ids[1],uuid));uint16_t port;
 assert(wnrs_agent_endpoint(source->session,uuid,&port)&&port==5054);
 assert(wnrs_app_endpoint(source->session,uuid,&port)&&port==43022);
 assert(wnsc_ready(node->catalog,uuid));char browse[2048];
 assert(wnsc_browse(node->catalog,"_sensorlink._tcp",clock_us,browse,sizeof browse)>2);
 assert(wnsc_browse_endpoints(node->catalog,"_sensorlink._tcp",clock_us,browse,sizeof browse)>2);
 const char type[]="_sensorlink._tcp";
 assert(wnrs_service_action(source->session,NULL,0,type,strlen(type),browse,sizeof browse,NULL,NULL)>2);
 uint8_t packet[40]={0x60};packet[6]=59;packet[7]=8;
 memcpy(packet+8,source->session->peer_address,16);memcpy(packet+24,address,16);uint64_t outgoing=0;
 assert(wnrs_packet_route(source->session,packet,sizeof packet,true,&outgoing)==1&&outgoing==expected_link&&packet[7]==7);
}
/* Begin at the existing verified-primary boundary; parser/crypto interop is
 * independently exercised by operator_lifecycle_normal and format fixtures. */
static void operator_admit(struct wnrs_node *node,struct wendy_pki_operator_peer *id,
                           const uint8_t instance[16],uint64_t revision,uint16_t sequence,
                           uint8_t address[16])
{
 char body[1024],envelope[1400],prefix[64],uuid[37];uint8_t signature[8]={0};
 assert(!wno_address(id->principal,strlen(id->principal),instance,address));
 assert(inet_ntop(AF_INET6,address,prefix,sizeof prefix));strcat(prefix,"/128");wn_uuid_format(instance,uuid);
 struct wn_writer w={.data=(uint8_t *)body,.capacity=sizeof body,.maximum=sizeof body};
 wn_map(&w,13);
 wn_key(&w,"version");wn_uint(&w,4);wn_key(&w,"device");wn_text(&w,"00000000-0000-0000-0000-000000000000");
 wn_key(&w,"owner");wn_map(&w,3);wn_key(&w,"principal");wn_text(&w,id->principal);
 wn_key(&w,"instance");wn_text(&w,uuid);wn_key(&w,"hashes");wn_array(&w,1);wn_bytes(&w,id->leaf_hash,32);
 wn_key(&w,"agentPort");wn_uint(&w,0);wn_key(&w,"revision");wn_uint(&w,revision);
 wn_key(&w,"Issued");wn_uint(&w,(uint64_t)node_unix(node));wn_key(&w,"Expires");wn_uint(&w,(uint64_t)node_unix(node)+60000);
 wn_key(&w,"route");wn_map(&w,3);wn_key(&w,"prefix");wn_text(&w,prefix);wn_key(&w,"routerId");wn_uint(&w,7007);wn_key(&w,"seqno");wn_uint(&w,sequence);
 wn_key(&w,"caps");wn_array(&w,0);wn_key(&w,"appEndpoints");wn_array(&w,0);wn_key(&w,"services");wn_array(&w,0);
 wn_key(&w,"agentTransport");wn_text(&w,"");wn_key(&w,"platform");wn_text(&w,"");int n=wn_finish(&w);assert(n>0);
 struct wn_writer outer={.data=(uint8_t *)envelope,.capacity=sizeof envelope,.maximum=sizeof envelope};
 wn_map(&outer,3);wn_key(&outer,"principal");wn_text(&outer,id->principal);wn_key(&outer,"body");wn_raw(&outer,body,(size_t)n);wn_key(&outer,"signature");wn_bytes(&outer,signature,sizeof signature);n=wn_finish(&outer);assert(n>0);
 struct wno_manifest proof;assert(!wno_manifest_read(envelope,(size_t)n,tenant,&proof));
 assert(!wnr_operator_manifest_verified(&node->core,&proof,id,node_unix(node),clock_us));
}
static void operator_handoff(struct wnrs_node *node,struct endpoint peers[2])
{
 struct wendy_pki_operator_peer id={.expires=1800003600};id.leaf_hash[0]=1;
 snprintf(id.principal,sizeof id.principal,"spiffe://wendy.sh/tenant/%s/operator/alice",tenant);
 uint8_t instance[16]={1},address[16];operator_admit(node,&id,instance,1,7,address);
 handoff_update(peers[0].session,address,7007,7,0);struct wb_route route;
 assert(wnr_lookup(&node->core,address,clock_us,&route)&&route.seqno==7);
 operator_admit(node,&id,instance,2,8,address);
 assert(wnr_lookup(&node->core,address,clock_us,&route)&&route.seqno==7);
 uint8_t packet[40]={0x60};packet[6]=59;packet[7]=8;memcpy(packet+8,peers[1].session->peer_address,16);memcpy(packet+24,address,16);uint64_t outgoing;
 assert(wnrs_packet_route(peers[1].session,packet,sizeof packet,true,&outgoing)==1&&outgoing==wnrs_link_id(peers[0].session));
 handoff_update(peers[1].session,address,7007,8,1000);
 assert(wnr_lookup(&node->core,address,clock_us,&route)&&route.seqno==8&&route.link==wnrs_link_id(peers[1].session));
 assert(!wno_authorizes(node->core.operators,address,7007,7,clock_us));
 memcpy(packet+8,peers[0].session->peer_address,16);packet[7]=8;
 assert(wnrs_packet_route(peers[0].session,packet,sizeof packet,true,&outgoing)==1&&outgoing==wnrs_link_id(peers[1].session));
}
struct export_probe { size_t bytes; bool unavailable; };
static int export_emit(void *ctx,const struct wg_message *message)
{
 struct export_probe *p=ctx;
 if(message->op==WG_DATA)p->bytes+=message->size;
 if(message->op==WG_UNAVAILABLE)p->unavailable=true;
 return 0;
}
static int no_export_input(void *ctx,const struct wg_id *id,const void *data,size_t size)
{(void)ctx;(void)id;(void)data;(void)size;assert(!"unexpected input");return -1;}
static bool servable(struct wnrs_node *node,const struct wg_id *id)
{
 struct wg_session request;assert(!wg_open(&node->pool,&request,1));
 struct export_probe probe={0};struct wg_message want={.op=WG_WANT,.id=*id,.request=1};
 assert(!wg_receive(&request,&want,(uint64_t)clock_us/1000,export_emit,no_export_input,&probe));
 unsigned turns=0;while(request.serving){assert(++turns<128);assert(!wg_poll(&request,(uint64_t)clock_us/1000,export_emit,&probe));}
 wg_close(&request);return probe.bytes>0&&!probe.unavailable;
}
static void new_key_repair(struct wnrs_node *node,struct endpoint *peer,const uint8_t address[16])
{
 struct wnd_entry *entry=handoff_claim(node,address);assert(entry&&entry->gossip_cached);
 int64_t lease=entry->lease_deadline_us,receipt=wnd_receipt_find(&node->core.directory,entry->device,clock_us)->receipt_deadline_us;
 struct wg_id old={.type=1};memcpy(old.hash,entry->gossip_hash,32);assert(servable(node,&old));
 uint8_t generated[256],public_key[128];int size=wendy_pki_generate_key_der(generated,sizeof generated);assert(size>0);
 mbedtls_pk_context replacement;mbedtls_pk_init(&replacement);
 assert(!mbedtls_pk_parse_key(&replacement,generated+sizeof generated-size,(size_t)size,NULL,0));
 int pub=mbedtls_pk_write_pubkey_der(&replacement,public_key,sizeof public_key);assert(pub>0);
 struct wendy_pki_mesh_peer renewed={.expires=1800003599};strcpy(renewed.device,ids[1]);
 memcpy(renewed.spki,public_key+sizeof public_key-pub,(size_t)pub);renewed.spki_size=(size_t)pub;
 renewed.signing_not_before=(time_t)(node_unix(node)/1000)-1;
 assert(!install_peer_identity(node,&renewed,clock_us));
 entry=handoff_claim(node,address);
 assert(!wnd_route_signature_current(entry)&&entry->lease_deadline_us==lease);
 assert(!servable(node,&old));char browse[2048];
 assert(wnsc_browse(node->catalog,"_sensorlink._tcp",clock_us,browse,sizeof browse)==2);
 uint8_t digest[32],signature[80];size_t signature_size;
 assert(!wendy_pki_mesh_digest(last_principal,last_body,last_body_size,digest));
 assert(!mbedtls_pk_sign(&replacement,MBEDTLS_MD_SHA256,digest,sizeof digest,signature,sizeof signature,&signature_size));
 char wire[1500];int wire_size=wn_manifest_wire_write(last_principal,last_body,last_body_size,signature,signature_size,wire,sizeof wire);assert(wire_size>0);
 struct wg_id id={.type=1};assert(!wn_gossip_identify(NULL,1,wire,(size_t)wire_size,id.hash));
 int result=complete(peer->session,&id,wire,(size_t)wire_size);unsigned attempts=0;
 while(result==WG_DEFER){assert(++attempts<8);(void)wendy_pki_work_poll();result=complete(peer->session,&id,wire,(size_t)wire_size);}
 assert(!result&&attempts);entry=handoff_claim(node,address);
 assert(wnd_route_signature_current(entry)&&entry->lease_deadline_us==lease&&entry->manifest.certificate_not_before==renewed.signing_not_before);
 assert(wnd_receipt_find(&node->core.directory,entry->device,clock_us)->receipt_deadline_us==receipt);
 assert(servable(node,&id)&&!servable(node,&old));
 /* Proof repair alone does not manufacture a route; the current candidate
  * still has to arrive before endpoint/catalog-owner readiness returns. */
 handoff_update(peer->session,address,entry->manifest.origin.router_id,entry->manifest.origin.seqno,0);
 uint16_t port;assert(wnrs_agent_endpoint(peer->session,entry->device,&port)&&port==5055);
 assert(wnsc_browse(node->catalog,"_sensorlink._tcp",clock_us,browse,sizeof browse)>2);
 mbedtls_pk_free(&replacement);
}
static int received_wire(struct endpoint *peer,const void *wire,size_t size,struct wg_id *id)
{
 assert(!wn_gossip_identify(NULL,1,wire,size,id->hash));id->type=1;
 int result=complete(peer->session,id,wire,size);unsigned attempts=0;
 while(result==WG_DEFER){assert(++attempts<8);(void)wendy_pki_work_poll();result=complete(peer->session,id,wire,size);}
 return result;
}
static void withdrawal_refresh(struct wnrs_node *node,struct endpoint *peer,
                                const struct wendy_pki_mesh_peer *original,const uint8_t address[16])
{
 time_t base=(time_t)(node_unix(node)/1000);
 node->clock.certificate_time=(struct wendy_pki_certificate_time){.seconds=base,.monotonic_us=clock_us,.uncertain=true,.generation=1};
 struct wendy_pki_mesh_peer signer=*original;signer.signing_not_before=base+10;
 assert(!install_peer_identity(node,&signer,clock_us));
 publish_withdraw=true;publication_offset_ms=20000;
 handoff_publish(peer,25,5054,true);publish_withdraw=false;publication_offset_ms=0;
 struct wnd_entry *e=handoff_claim(node,address);assert(e->manifest.withdraw&&!e->handoff);
 int64_t lease=e->lease_deadline_us,floor=wnd_receipt_find(&node->core.directory,e->device,clock_us)->receipt_deadline_us;
 struct wg_id first={.type=1};memcpy(first.hash,e->gossip_hash,32);assert(servable(node,&first));
 time_t first_nb=e->manifest.certificate_not_before;
 signer.signing_not_before=base-1;assert(!install_peer_identity(node,&signer,clock_us));
 struct wg_id repeated;assert(!received_wire(peer,last_wire,last_wire_size,&repeated));
 assert(e->manifest.certificate_not_before==first_nb); /* Existing same-id cache keeps original signer dates. */
 /* A different optional envelope cannot borrow dates when the verified body
  * encounters ordinary cache pressure instead of retaining its new wire. */
 struct wn_doc doc;const uint8_t *old_signature;size_t old_signature_size;
 assert(!wn_doc_parse(&doc,last_wire,last_wire_size));
 assert(!wn_doc_bytes(&doc,wn_doc_member(&doc,0,"signature"),&old_signature,&old_signature_size));
 char pressured[1600];struct wn_writer out={.data=(uint8_t *)pressured,.capacity=sizeof pressured,.maximum=sizeof pressured};
 wn_map(&out,4);wn_key(&out,"principal");wn_text(&out,last_principal);wn_key(&out,"body");wn_raw(&out,last_body,last_body_size);
 wn_key(&out,"signature");wn_bytes(&out,old_signature,old_signature_size);wn_text(&out,"optional-test");wn_uint(&out,1);
 int pressured_size=wn_finish(&out);assert(pressured_size>0);pressure_wire=pressured;
 struct wg_id unretained;assert(!received_wire(peer,pressured,(size_t)pressured_size,&unretained));pressure_wire=NULL;
 assert(!servable(node,&unretained)&&e->manifest.certificate_not_before==first_nb&&e->lease_deadline_us==lease);
 node->clock.certificate_time.uncertain=false;expire_announcements(node,clock_us);
 assert(!servable(node,&first)&&e->lease_deadline_us==lease);
 uint8_t signature[80];size_t sig_size;assert(!wendy_pki_mesh_sign(NULL,last_principal,last_body,last_body_size,signature,&sig_size));
 char wire[1500];int n=wn_manifest_wire_write(last_principal,last_body,last_body_size,signature,sig_size,wire,sizeof wire);assert(n>0);
 struct wg_id repaired;assert(!received_wire(peer,wire,(size_t)n,&repaired));
 assert(servable(node,&repaired)&&e->manifest.certificate_not_before==signer.signing_not_before);
 assert(e->lease_deadline_us<=lease&&wnd_receipt_find(&node->core.directory,e->device,clock_us)->receipt_deadline_us==floor);
 assert(!wnd_authorizes(&node->core.directory,address,e->manifest.origin.router_id,e->manifest.origin.seqno,clock_us));
 int64_t unchanged=e->lease_deadline_us;time_t unchanged_nb=e->manifest.certificate_not_before;
 uint8_t bad[8]={0};n=wn_manifest_wire_write(last_principal,last_body,last_body_size,bad,sizeof bad,wire,sizeof wire);assert(n>0);
 struct wg_id rejected;assert(received_wire(peer,wire,(size_t)n,&rejected)<0);
 assert(e->lease_deadline_us==unchanged&&e->manifest.certificate_not_before==unchanged_nb&&servable(node,&repaired));
}
/* Key-cache eviction must not make an old withdrawal appear to retain a
 * verified binding when a different key is installed for the same origin. */
static void withdrawal_key_eviction(struct wnrs_node *node,struct endpoint *peer,
                                    const struct wendy_pki_mesh_peer *original,const uint8_t address[16])
{
 struct wnd_entry *e=handoff_claim(node,address);assert(e&&e->manifest.withdraw&&e->gossip_cached);
 int64_t lease=e->lease_deadline_us,floor=wnd_receipt_find(&node->core.directory,e->device,clock_us)->receipt_deadline_us;
 struct wg_id old={.type=1};memcpy(old.hash,e->gossip_hash,32);assert(servable(node,&old));
 for(struct wnd_entry *pin=node->core.directory.entries;pin;pin=pin->next)pin->key_pinned=pin!=e;
 e->key_pinned=false;assert(!wnd_key_limit(&node->core.directory,1));
 assert(!e->peer.spki_size&&servable(node,&old));assert(!wnd_key_limit(&node->core.directory,2));
 uint8_t private_der[256],spki[128];int n=wendy_pki_generate_key_der(private_der,sizeof private_der);assert(n>0);
 mbedtls_pk_context replacement;mbedtls_pk_init(&replacement);
 assert(!mbedtls_pk_parse_key(&replacement,private_der+sizeof private_der-n,(size_t)n,NULL,0));
 int pub=mbedtls_pk_write_pubkey_der(&replacement,spki,sizeof spki);assert(pub>0);
 struct wendy_pki_mesh_peer changed=*original;
 memcpy(changed.spki,spki+sizeof spki-pub,(size_t)pub);changed.spki_size=(size_t)pub;
 assert(!install_peer_identity(node,&changed,clock_us));
 assert(!servable(node,&old)&&!e->gossip_retired&&e->lease_deadline_us==lease);
 struct wg_id rejected;assert(received_wire(peer,last_wire,last_wire_size,&rejected)<0);
 struct wendy_pki_mesh_peer restored=*original;restored.signing_not_before=(time_t)(node_unix(node)/1000)-1;
 assert(!install_peer_identity(node,&restored,clock_us));
 struct wg_id repaired;assert(!received_wire(peer,last_wire,last_wire_size,&repaired));
 assert(servable(node,&repaired)&&e->lease_deadline_us<=lease);
 assert(wnd_receipt_find(&node->core.directory,e->device,clock_us)->receipt_deadline_us==floor);
 mbedtls_pk_free(&replacement);
}
/* A newly observed restrictive certificate path is a real trust change,
 * not a pure sequence refresh. Apply it immediately, even while a replacement
 * body still needs verification; failure must not restore old authority. */
static void restrictive_path_transition(struct wnrs_node *node,struct endpoint *peer,
                                         const struct wendy_pki_mesh_peer *original,const uint8_t address[16])
{
 struct wnd_entry *e=handoff_claim(node,address);assert(e&&e->handoff&&e->handoff->has_prior);
 struct wendy_pki_mesh_peer short_path=*original;
 short_path.expires=(time_t)(node_unix(node)/1000)+40;
 assert(!install_peer_identity(node,&short_path,clock_us));
 assert(!e->handoff->has_prior&&!wnd_route_signature_current(e));
 struct wb_route route;assert(!wnr_lookup(&node->core,address,clock_us,&route));
 uint8_t bad[8]={0};char invalid[1500];
 int n=wn_manifest_wire_write(last_principal,last_body,last_body_size,bad,sizeof bad,invalid,sizeof invalid);assert(n>0);
 struct wg_id rejected;assert(received_wire(peer,invalid,(size_t)n,&rejected)<0);
 assert(!wnr_lookup(&node->core,address,clock_us,&route));
 publication_duration_ms=20000;
 handoff_publish(peer,e->manifest.origin.seqno,5054,true);publication_duration_ms=60000;
 assert(wnd_route_signature_current(e)&&!e->handoff->has_prior);
 handoff_update(peer->session,address,e->manifest.origin.router_id,e->manifest.origin.seqno,0);
 assert(wnr_lookup(&node->core,address,clock_us,&route));
 assert(!install_peer_identity(node,original,clock_us));
}
/* CURRENT topology projections expose the effective certificate-path cap,
 * even when a stale absolute Issued gives this receiver a longer local TTL. */
static void current_topology_cap(struct wnrs_node *node,struct endpoint *peer,
                                   const struct wendy_pki_mesh_peer *original,const uint8_t address[16])
{
 struct wendy_pki_mesh_peer short_path=*original;
 short_path.expires=(time_t)(node_unix(node)/1000)+30;
 assert(!install_peer_identity(node,&short_path,clock_us));
 struct wnd_entry *e=handoff_claim(node,address);uint16_t seq=e->manifest.origin.seqno;
 publication_offset_ms=-890000;publication_duration_ms=900000;
 handoff_publish(peer,seq,5054,true);publication_offset_ms=0;publication_duration_ms=60000;
 assert(e->lease_deadline_us==clock_us+INT64_C(900000000));
 handoff_update(peer->session,address,e->manifest.origin.router_id,seq,0);
 int64_t cap=wnd_route_deadline(&node->core.directory,address,e->manifest.origin.router_id,seq,clock_us);
 assert(cap==clock_us+INT64_C(30000000));bool route=false,announcement=false;
 for(unsigned i=0;i<128;i++){
  struct wnt_record_view view={.record=WendyComNetTopologyRecord_init_zero};
  if(!topology_record(node,i,clock_us,&view))break;
  if((view.record.kind==2||view.record.kind==3)&&view.record.device.size==16&&
     !memcmp(view.record.device.bytes,e->device,16)){
   assert(view.record.authorized&&view.lease_deadline_us==cap);
   assert(view.record.expires_at_unix_ms==node_unix(node)+30000);
   if(view.record.kind==2)route=true;else announcement=true;
  }
 }
 assert(route&&announcement);assert(!install_peer_identity(node,original,clock_us));
}
static bool defer_checkpoint;
static int handoff_checkpoint(void *ctx,const void *data,size_t size)
{(void)ctx;assert(data&&size);return defer_checkpoint?1:0;}
int main(int argc,char **argv)
{
 assert(argc==2&&!wendy_pki_crypto_init());
#if defined(WENDY_NET_MEMORY_HOST_BUDGET_TEST)
 assert(wendy_net_runtime_memory_open());
#endif
 FILE*f=fopen(argv[1],"rb");assert(f);uint8_t der[512];size_t n=fread(der,1,sizeof der,f);fclose(f);
 mbedtls_pk_init(&key);assert(!mbedtls_pk_parse_key(&key,der,n,NULL,0));
 uint8_t spki[128];int spki_size=mbedtls_pk_write_pubkey_der(&key,spki,sizeof spki);assert(spki_size>0);
 struct wendy_pki_mesh_identity identity={.verified_seconds=1800000000,.verified_monotonic_us=1000000,.certificate_expires=1800003600,.config_generation=1};
 strcpy(identity.tenant,tenant);strcpy(identity.device,ids[0]);struct wnrs_node*node=NULL;
 struct endpoint peers[2]={{.index=1},{.index=2}};wendy_pki_connection connections[2]={0};
 for(unsigned i=0;i<2;i++){
  strcpy(connections[i].peer.device,ids[i+1]);connections[i].peer.expires=1800003600;connections[i].peer.spki_size=(size_t)spki_size;
  memcpy(connections[i].peer.spki,spki+sizeof spki-spki_size,(size_t)spki_size);
  assert(!wnrs_open(&peers[i].session,&node,&connections[i],&identity,ids[i+1],i?WNR_BLE_COST:WNR_LAN_COST,send_frame,&peers[i]));
  remote_open(&peers[i],i?WNR_BLE_COST:WNR_LAN_COST);
 }
 drain();
 for(unsigned step=0;step<200;step++){clock_us+=100000;for(unsigned i=0;i<2;i++){
  remote_finish(&peers[i],wb_tick(&peers[i].remote,milliseconds()));assert(!wnrs_tick(peers[i].session));}drain();}
 wendy_pki_work_enable();uint8_t address[16];memcpy(address,peers[0].session->peer_address,16);
 struct wb_route route;assert(wnr_lookup(&node->core,address,clock_us,&route));uint16_t old=route.seqno;uint64_t router=route.router;
 handoff_publish(&peers[0],old,5054,true);
 assert(!wnr_tick(&node->core,node_unix(node),clock_us));drop_frames();
 int64_t lease=handoff_claim(node,address)->lease_deadline_us;
 struct wg_id old_artifact={.type=1};memcpy(old_artifact.hash,handoff_claim(node,address)->gossip_hash,32);
 assert(servable(node,&old_artifact));
 live_consumers(node,&peers[1],address,route.link);
 handoff_publish(&peers[0],(uint16_t)(old+1),5054,false);
 assert(wnr_lookup(&node->core,address,clock_us,&route)&&route.seqno==old);
 assert(wnd_authorizes(&node->core.directory,address,router,old,clock_us));
 assert(wnd_authorizes(&node->core.directory,address,router,(uint16_t)(old+1),clock_us));
 assert(handoff_claim(node,address)->handoff->prior.deadline_us==lease);
 handoff_publish(&peers[0],(uint16_t)(old+1),5054,false);
 assert(handoff_claim(node,address)->handoff->has_prior&&handoff_claim(node,address)->handoff->prior.origin.seqno==old);
 clock_us+=100000;
 handoff_publish(&peers[0],(uint16_t)(old+2),5054,true);
 assert(wnd_authorizes(&node->core.directory,address,router,old,clock_us));
 assert(!wnd_authorizes(&node->core.directory,address,router,(uint16_t)(old+1),clock_us));
 assert(handoff_claim(node,address)->handoff->prior.deadline_us==lease);
 assert(wnr_lookup(&node->core,address,clock_us,&route)&&route.seqno==old);
 live_consumers(node,&peers[1],address,route.link);
 assert(!servable(node,&old_artifact));
 /* Selected old route and current new announcement coexist in the existing DTO. */
 bool selected=false,current=false;
 for(unsigned i=0;;i++){
  struct wnt_record_view view={.record=WendyComNetTopologyRecord_init_zero};if(!topology_record(node,i,clock_us,&view))break;
  if(view.record.kind==2&&view.record.router_id==router&&view.record.sequence==old){selected=true;assert(view.lease_deadline_us==lease&&view.record.authorized);}
  if(view.record.kind==3&&view.record.router_id==router&&view.record.sequence==(uint16_t)(old+2))current=true;
 }
 assert(selected&&current);
 /* A more expensive, nonselected current candidate must complete promotion. */
 handoff_update(peers[1].session,address,router,(uint16_t)(old+2),1000);
 assert(wnr_lookup(&node->core,address,clock_us,&route));
 assert(route.seqno==(uint16_t)(old+2)&&route.link==wnrs_link_id(peers[1].session));
 assert(!wnd_authorizes(&node->core.directory,address,router,old,clock_us));
 assert(!handoff_claim(node,address)->handoff->has_prior);drop_frames();
 node->core.config.persist=handoff_checkpoint;defer_checkpoint=true;
 handoff_publish(&peers[0],(uint16_t)(old+3),5054,false);
 assert(handoff_claim(node,address)->pending_receipt);
 assert(wnr_lookup(&node->core,address,clock_us,&route)&&route.seqno==(uint16_t)(old+2));
 struct wb_prefix pending_prefix={.family=6,.bits=128};memcpy(pending_prefix.bytes,address,16);
 assert(!node->core.babel.config.allow(node->core.babel.config.context,router,&pending_prefix,(uint16_t)(old+3)));
 defer_checkpoint=false;assert(!wnr_tick(&node->core,node_unix(node),clock_us));
 assert(!handoff_claim(node,address)->pending_receipt);node->core.config.persist=NULL;
 handoff_update(peers[0].session,address,router,(uint16_t)(old+3),WB_INFINITY);
 assert(handoff_claim(node,address)->handoff->has_prior);
 assert(wnd_authorizes(&node->core.directory,address,router,(uint16_t)(old+2),clock_us));
 operator_handoff(node,peers);drop_frames();
 restrictive_path_transition(node,&peers[0],&connections[0].peer,address);drop_frames();
 current_topology_cap(node,&peers[0],&connections[0].peer,address);drop_frames();
 /* Non-route capability changes revoke the old tuple immediately. */
 handoff_publish(&peers[0],(uint16_t)(old+4),5055,true);
 assert(!handoff_claim(node,address)->handoff->has_prior);
 assert(!wnd_authorizes(&node->core.directory,address,router,(uint16_t)(old+2),clock_us));drop_frames();
 new_key_repair(node,&peers[0],address);drop_frames();
 withdrawal_refresh(node,&peers[0],&connections[0].peer,address);drop_frames();
 withdrawal_key_eviction(node,&peers[0],&connections[0].peer,address);drop_frames();
 for(unsigned i=0;i<2;i++){wnrs_close(peers[i].session);peers[i].session=NULL;wb_deinit(&peers[i].remote);}
 wnrs_node_reset(&node);assert(!node);drop_frames();mbedtls_pk_free(&key);
#if defined(WENDY_NET_MEMORY_HOST_BUDGET_TEST)
 wendy_net_runtime_memory_close();assert(wendy_net_runtime_memory_drained());
#endif
 puts("Atomic handoff: deferred verification, old bounds, higher metric promotion and revocation PASS");return 0;
}
