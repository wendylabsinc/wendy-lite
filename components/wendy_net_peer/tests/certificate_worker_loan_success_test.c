/* Ordinary queued completion/cancellation lifetime, independent of cache/node. */
#include "../src/certificate_worker.h"
#include "wendy_pki_crypto.h"
#include "wendy_net_alloc.h"
#include "wendy_pki_work.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static void (*pending)(void *);static void *pending_context,*workspace_owner;
static uint8_t expected[1500],baseline[900],baseline_hash[32];
static bool baseline_enabled;
int wendy_pki_mesh_local_part(const struct wendy_pki_mesh_identity *identity,const uint8_t hash[32],
    size_t offset,uint8_t out[1024],size_t *total)
{
    assert(identity->config_generation==17);*total=0;
    if(!baseline_enabled || memcmp(hash,baseline_hash,32) || offset>=sizeof baseline)return -1;
    *total=sizeof baseline;if(!out)return 1;
    size_t n=sizeof baseline-offset;if(n>1024)n=1024;memcpy(out,baseline+offset,n);return (int)n;
}
static int baseline_read(void *context,const uint8_t hash[32],size_t offset,uint8_t out[1024],size_t *total)
{int n=wendy_pki_mesh_local_part(context,hash,offset,out,total);return n>0 ? 1:n==-1 ? 0:n;}

bool wendy_pki_handshake_busy(void){return workspace_owner!=NULL;}
bool wendy_pki_handshake_claim(void *owner){if(workspace_owner)return false;workspace_owner=owner;return true;}
void wendy_pki_handshake_release(void *owner){assert(workspace_owner==owner);workspace_owner=NULL;}
bool wendy_pki_work_submit(void (*function)(void *),void *context)
{assert(!pending);pending=function;pending_context=context;return true;}
int wn_principal_device(const char *principal,const char *tenant,uint8_t output[16])
{assert(strlen(principal)==105 && strlen(tenant)==36);memset(output,0,16);return 0;}
int wendy_pki_mesh_verify_snapshot(const struct wendy_pki_mesh_identity *identity,
    const uint8_t *const *parts,const size_t *sizes,size_t count,struct wendy_pki_mesh_peer *peer)
{
    assert(identity->config_generation==17 && count==(baseline_enabled ? 2u:1u) && sizes[0]==sizeof expected);
    assert(!memcmp(parts[0],expected,sizeof expected));
    if(baseline_enabled){
        assert(sizes[1]==sizeof baseline && !memcmp(parts[1],baseline,sizeof baseline));
        assert(!wendy_pki_input_workspace_cached_bytes()); /* actual26KiB loan in use, no second assembly allocation */
    }
    strcpy(peer->device,"00000000-0000-4000-8000-000000000004");return 0;
}
int main(void)
{
    for(unsigned scenario=0;scenario<3;scenario++){
        assert(wendy_net_runtime_memory_open());
        struct wncs_store store;assert(!wncs_open_limits(&store,8192,4,2));
        struct wncf_chain chain={.count=1};
        strcpy(chain.principal,"spiffe://wendy.sh/tenant/2558fd76-afc7-466e-9613-6b715296a526/device/00000000-0000-4000-8000-000000000004");
        for(size_t i=0;i<sizeof expected;i++)expected[i]=(uint8_t)(i*13+scenario);
        assert(!wendy_pki_sha256(expected,sizeof expected,chain.hashes[0]));
        assert(!wncs_put(&store,chain.hashes[0],expected,sizeof expected));
        struct wendy_pki_mesh_identity identity={.config_generation=17};
        strcpy(identity.tenant,"2558fd76-afc7-466e-9613-6b715296a526");
        baseline_enabled=scenario==2;
        if(baseline_enabled){
            for(size_t i=0;i<sizeof baseline;i++)baseline[i]=(uint8_t)(i*7);
            assert(!wendy_pki_sha256(baseline,sizeof baseline,baseline_hash));
            wncs_set_baseline(&store,&identity,baseline_read);
            assert(!wncs_put(&store,baseline_hash,baseline,sizeof baseline));assert(store.count==1);
            memcpy(chain.hashes[1],baseline_hash,32);chain.count=2;
            wendy_net_memory_scope_t old=wendy_net_runtime_scope_enter();
            wendy_pki_input_workspace_active(true);wendy_net_memory_scope_leave(old);
            assert(wendy_pki_input_workspace_cached_bytes()==26624);
        }
        struct wncv_job *job=NULL;assert(!wncv_start(&job,&store,&chain,&identity) && job && pending);
        assert(!atomic_load(&job->done) && wendy_pki_handshake_busy());
        if(scenario==1){wncv_release(job);job=NULL;} /* carrier goes away before worker starts */
        if(!baseline_enabled){wncs_close(&store);wendy_net_runtime_memory_close();assert(!wendy_net_runtime_memory_drained());}
        void (*run)(void*)=pending;void *context=pending_context;pending=NULL;pending_context=NULL;
        wendy_net_memory_scope_t old=wendy_net_runtime_scope_enter();run(context);wendy_net_memory_scope_leave(old);
        if(job){assert(atomic_load(&job->done) && !job->result && wendy_pki_handshake_busy());wncv_release(job);}
        if(baseline_enabled){
            assert(wendy_pki_input_workspace_cached_bytes()==26624);
            wendy_pki_input_workspace_active(false);
            assert(wncs_trim(&store)>0 && !store.count && !store.bytes);
            size_t total=0;assert(!wncs_read(&store,chain.hashes[0],0,NULL,&total));
            assert(wncs_read(&store,baseline_hash,0,NULL,&total)==1 && total==sizeof baseline);
            wncs_close(&store);wendy_net_runtime_memory_close();
        }
        assert(!wendy_pki_handshake_busy() && wendy_net_runtime_memory_drained());
    }
    puts("Queued certificate verification keeps DER alive after close and drains on normal or cancelled completion");return 0;
}
