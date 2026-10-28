/* Positive current Go v4 → actual actor completion/crypto-worker/DER fetch. */
#define WENDY_NET_REAL_CERT_RELAY_TEST 1
#define WENDY_NET_REAL_OPERATOR_RELAY_TEST 1
#define main existing_shared_router_main
#include "router_node_success_test.c"
#undef main
#include "wendy_pki_operator.h"
#include <mbedtls/platform.h>
#include <psa/crypto_extra.h>
static uint8_t *operator_roots;static size_t operator_roots_size;
int wncv_start(struct wncv_job **out,struct wncs_store *store,const struct wncf_chain *chain,const struct wendy_pki_mesh_identity *clock)
{(void)out;(void)store;(void)chain;(void)clock;return 1;}
void wncv_release(struct wncv_job *job){assert(!job);}
bool wendy_pki_operator_snapshot_current(const struct wendy_pki_mesh_identity *clock)
{return clock->config_generation==17;}
int wendy_pki_operator_verify_snapshot(const struct wendy_pki_mesh_identity *clock,const uint8_t *const *parts,const size_t *sizes,size_t count,struct wendy_pki_operator_peer *peer)
{assert(clock->config_generation==17);return wendy_pki_operator_chain(parts,sizes,count,operator_roots,operator_roots_size,clock->tenant,clock->verified_seconds,peer);}
static uint8_t *load_operator(const char *path,size_t *size)
{FILE *f=fopen(path,"rb");assert(f);assert(!fseek(f,0,SEEK_END));long n=ftell(f);assert(n>0 && n<128*1024);rewind(f);uint8_t *p=malloc((size_t)n);assert(p && fread(p,1,(size_t)n,f)==(size_t)n);fclose(f);*size=(size_t)n;return p;}
static int operator_publish(void *context,const struct wn_origin *origin,int64_t wall,int64_t now)
{(void)context;(void)origin;(void)wall;(void)now;return 0;}
static int operator_discard(void *context,uint64_t link,const void *data,size_t size)
{(void)context;(void)link;(void)data;(void)size;return 0;}
static int operator_send(void *context,const void *data,size_t size,bool control)
{(void)context;(void)data;(void)size;(void)control;return 0;}
static void deliver_normal(struct wnrs *session,const uint8_t *wire,size_t size)
{
 struct wg_id id={.type=1};assert(!wn_gossip_identify(NULL,1,wire,size,id.hash));
 assert(complete(session,&id,wire,size)==WG_DEFER && session->operator_verification);
 assert(wendy_pki_work_poll());
 assert(!complete(session,&id,wire,size) && !session->operator_verification && !wnrs_receive_paused(session));
}
int main(int argc,char **argv)
{
 assert(argc==4 || argc==5 || argc==8);
 assert(!mbedtls_platform_set_calloc_free(wendy_net_memory_scoped_calloc,wendy_net_memory_scoped_free));
 assert(mbedtls_psa_set_key_slot_table_allocator(wendy_pki_crypto_shared_calloc)==PSA_SUCCESS);
 assert(!wendy_pki_crypto_init());size_t leaf_size,wire_size;
 uint8_t *leaf=load_operator(argv[1],&leaf_size),*wire=load_operator(argv[3],&wire_size);
 operator_roots=load_operator(argv[2],&operator_roots_size);
 struct wno_manifest proof;
 int parsed=wno_manifest_read(wire,wire_size,"11111111-1111-4111-8111-111111111111",&proof);
 if(argc==5){
  assert(!strcmp(argv[4],"unsupported") && parsed==WNO_UNSUPPORTED);
  struct wnrs_node ignored={0};strcpy(ignored.clock.tenant,"11111111-1111-4111-8111-111111111111");
  struct wnrs session={.node=&ignored};struct wg_id id={.type=1};
  assert(!complete_operator(&session,&id,wire,wire_size) && !session.operator_verification && !ignored.core.operators);
  free(leaf);free(wire);free(operator_roots);puts("larger valid operator signature is unsupported without carrier teardown PASS");return 0;
 }
 assert(!parsed);
 wendy_pki_work_enable();assert(wendy_net_runtime_memory_open());
 wendy_net_memory_scope_t prior=wendy_net_runtime_scope_enter();
 struct wnrs_node *node=wendy_net_calloc(1,sizeof *node);assert(node);
 struct wnr_config cfg={.tenant="11111111-1111-4111-8111-111111111111",.device="55555555-5555-4555-8555-555555555555",.router=55,.seed=1,.publish=operator_publish,.send=operator_discard};
 assert(!wnr_init(&node->core,&cfg,clock_us,NULL,0) && !wnr_start(&node->core,proof.issued,clock_us));
 strcpy(node->clock.tenant,cfg.tenant);strcpy(node->clock.device,cfg.device);node->clock.config_generation=17;node->clock.verified_seconds=(time_t)(proof.issued/1000);node->clock.verified_monotonic_us=clock_us;
 assert(!wncs_open_limits(&node->certificates,32768,8,4));
 struct wg_config pool={.objects=8,.pending=8,.bytes=32768,.identify=wn_gossip_identify,.fifo=true};assert(!wg_init(&node->pool,&pool));
 struct wnrs session={.node=node,.link=1,.send=operator_send};node->sessions=&session;session.identity=node->clock;
 struct wg_id id={.type=1};assert(!wn_gossip_identify(NULL,1,wire,wire_size,id.hash));
 /* A cold current manifest asks by exact signed DER hashes, not a device-only
  * descriptor. Complete bytes remain bounded by the existing download owner. */
 assert(complete(&session,&id,wire,wire_size)==WG_DEFER && session.fetch.chain && !session.fetch.chain->principal[0]);
 assert(!wncs_put(&node->certificates,proof.hashes[0],leaf,leaf_size));
 assert(!certificate_tick(&session) && !session.fetch.chain);
 assert(complete(&session,&id,wire,wire_size)==WG_DEFER && session.operator_verification && wnrs_receive_paused(&session));
 /* Temporary ordinary budget pressure is a retry, not a bad signature. */
 wendy_net_memory_snapshot_t held;wendy_net_runtime_memory_snapshot(&held);
 wendy_net_memory_reservation_t pressure={0};
 assert(wendy_net_memory_reserve(wendy_net_runtime_memory_ledger(),&pressure,
     held.limit_bytes-held.current_bytes,WENDY_NET_MEMORY_INTERNAL));
 assert(wendy_pki_work_poll() && atomic_load(&session.operator_verification->done));
 assert(session.operator_verification->result==1);
 wendy_net_memory_release(&pressure);
 assert(complete(&session,&id,wire,wire_size)==WG_DEFER && !session.operator_verification);
 assert(complete(&session,&id,wire,wire_size)==WG_DEFER && !session.operator_verification);
 clock_us+=250001;
 deliver_normal(&session,wire,wire_size);
 assert(node->core.operators && node->core.operators->count==1 && node->core.operators->entries->gossip_cached);
 /* Full manifest relay uses the ordinary pool and therefore its FIFO/GONE
  * accounting. Forgetting bytes keeps the signed-origin receipt. */
 assert(!known_artifact(node,&id));evicted_artifact(node,&id,wire,wire_size);assert(known_artifact(node,&id));
 /* UI rows borrow the real typed identity during scans. Only the exported
  * selected page owns a copy; it survives ordinary receipt expiry. */
 struct wno_entry *entry=node->core.operators->entries;
 wendy_net_memory_snapshot_t before,after;wendy_net_runtime_memory_snapshot(&before);
 struct wnt_record_view view={.record=WendyComNetTopologyRecord_init_zero};
 assert(wnrs_topology_operator_row(node,3,0,clock_us,&view)==1);
 assert(view.principal==entry->principal && view.principal_size==proof.principal_size);
 assert(view.record.owner_role==WNT_TOPOLOGY_OPERATOR && !view.record.device.size);
 assert(view.record.owner_instance.size==16 && !memcmp(view.record.owner_instance.bytes,proof.instance,16));
 assert(view.record.address.size==16 && !memcmp(view.record.address.bytes,proof.address,16));
 assert(view.record.router_id==proof.origin.router_id && view.record.sequence==proof.origin.seqno && view.record.authorized);
 struct wnt_record_view route={.record=WendyComNetTopologyRecord_init_zero};
 route.record.address.size=16;memcpy(route.record.address.bytes,proof.address,16);
 route.record.router_id=proof.origin.router_id;route.record.sequence=proof.origin.seqno;
 assert(wnrs_topology_operator_row(node,2,0,clock_us,&route)==1 && route.record.authorized);
 assert(route.principal==entry->principal && !route.record.device.size);
 node->core.config.endpoint_gateway=true;
 assert(!wnrs_topology_operator_row(node,3,0,clock_us,&route));
 node->core.config.endpoint_gateway=false;
 wendy_net_runtime_memory_snapshot(&after);assert(before.current_bytes==after.current_bytes);
 WendyComNetTopologyPage page=WendyComNetTopologyPage_init_zero;
 unsigned cursor=0;uint64_t generation=0;bool exported=false;
 do{
  assert(!wnrs_topology(node,cursor,generation,&page));generation=page.generation;cursor=page.next_cursor;
  if(page.has_record && page.record.owner_role==WNT_TOPOLOGY_OPERATOR){exported=true;break;}
 }while(cursor);
 assert(exported && page.record.owner_principal.arg && page.record.owner_principal.arg!=entry->principal);
 assert(!memcmp(page.record.owner_principal.arg,proof.principal,proof.principal_size));
 wno_expire(node->core.operators,entry->retain_until_us+1);
 assert(!node->core.operators->entries && !memcmp(page.record.owner_principal.arg,proof.principal,proof.principal_size));
 wnt_page_release(&page);
 if(argc==8){
  /* The existing page lifetime case reaped its receipt. Re-admit a valid live
   * origin, then exercise ordinary refresh/stale/capacity/withdrawal traffic. */
  deliver_normal(&session,wire,wire_size);
  size_t refresh_size,stale_size,withdraw_size,other_size;
  uint8_t *refresh=load_operator(argv[4],&refresh_size),*stale=load_operator(argv[5],&stale_size);
  uint8_t *withdraw=load_operator(argv[6],&withdraw_size),*other=load_operator(argv[7],&other_size);
  deliver_normal(&session,refresh,refresh_size);
  assert(node->core.operators->entries->revision==43);
  deliver_normal(&session,stale,stale_size);
  assert(node->core.operators->entries->revision==43);
  node->core.operators->limit=1;
  deliver_normal(&session,other,other_size);
  assert(node->core.operators->count==1);
  deliver_normal(&session,withdraw,withdraw_size);
  entry=node->core.operators->entries;
  assert(entry->revision==44 && !entry->deadline_us && entry->gossip_cached);
  assert(!wno_live_address(node->core.operators,entry->address,clock_us));
  wg_prune(&node->pool,(uint64_t)clock_us/1000+1);
  assert(node->pool.object_count==1); /* The signed withdrawal is relayable. */
  free(refresh);free(stale);free(withdraw);free(other);
 }
 printf("Actual actor primary operator chain/signature worker admission and exact-hash repair PASS (%zu native core bytes)\n",wnr_memory(&node->core));
 /* An owner may close while a queued proof still owns its immutable input
  * and DER loan. The worker must finish without borrowing the dead node. */
 struct wnop_job *closing=NULL;
 assert(!wnop_job_start(&closing,&node->certificates,wire,wire_size,&node->clock,NULL));
 wnop_job_release(closing);
 wg_deinit(&node->pool);wncs_close(&node->certificates);wnr_deinit(&node->core);wendy_net_free(node);
 assert(wendy_pki_work_poll());
 wendy_pki_crypto_cleanup();
 wendy_net_memory_scope_leave(prior);
 wendy_net_runtime_memory_close();
 assert(wendy_net_runtime_memory_drained());
 free(leaf);free(wire);free(operator_roots);return 0;
}
