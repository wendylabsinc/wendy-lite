/* Positive current Go v4 → actual actor completion/crypto-worker/DER fetch. */
#define WENDY_NET_REAL_CERT_RELAY_TEST 1
#define WENDY_NET_REAL_OPERATOR_RELAY_TEST 1
#define main existing_shared_router_main
#include "router_node_success_test.c"
#undef main
#include "wendy_pki_operator.h"
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
int main(int argc,char **argv)
{
 assert(argc==4 && !wendy_pki_crypto_init());size_t leaf_size,wire_size;
 uint8_t *leaf=load_operator(argv[1],&leaf_size),*wire=load_operator(argv[3],&wire_size);
 operator_roots=load_operator(argv[2],&operator_roots_size);
 struct wno_manifest proof;assert(!wno_manifest_read(wire,wire_size,"11111111-1111-4111-8111-111111111111",&proof));
 wendy_pki_work_enable();assert(wendy_net_runtime_memory_open());
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
 assert(wendy_pki_work_poll());
 assert(atomic_load(&session.operator_verification->done));
 assert(!complete(&session,&id,wire,wire_size) && !session.operator_verification && !wnrs_receive_paused(&session));
 assert(node->core.operators && node->core.operators->count==1 && node->core.operators->entries->gossip_cached);
 /* Full manifest relay uses the ordinary pool and therefore its FIFO/GONE
  * accounting. Forgetting bytes keeps the signed-origin receipt. */
 assert(!known_artifact(node,&id));evicted_artifact(node,&id,wire,wire_size);assert(known_artifact(node,&id));
 printf("Actual actor primary operator chain/signature worker admission and exact-hash repair PASS (%zu native core bytes)\n",wnr_memory(&node->core));
 wg_deinit(&node->pool);wncs_close(&node->certificates);wnr_deinit(&node->core);wendy_net_free(node);
 wendy_net_runtime_memory_close();assert(wendy_net_runtime_memory_drained());
 free(leaf);free(wire);free(operator_roots);return 0;
}
