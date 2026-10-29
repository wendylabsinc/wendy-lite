/* SPDX-License-Identifier: Apache-2.0 */
#include "certificate_worker.h"
#include "wendy_net_alloc.h"
#include "certificate_store.h"
#include "wendy_net_peer_protocol.h"
#include "wendy_pki_work.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include <stdlib.h>
#include <string.h>

void wncv_release(struct wncv_job *job)
{
    if(job && atomic_fetch_sub(&job->references,1)==1){
        /* DER/crypto temporaries are already gone. Keep this small cookie
         * alive until the owner CAS, so a new allocation cannot reuse it. */
        wncs_unpin(&job->loan);
        if(job->workspace_owned)wendy_pki_handshake_release(job);
        wendy_net_free(job);
    }
}
static void verify(void *context)
{
    struct wncv_job *job=context;
    uint8_t device[16];uint8_t *workspace=NULL;size_t capacity=0;bool workspace_borrowed=false;
    job->result=-1;
    size_t missing=0;
    for(unsigned i=0;i<job->loan.count;i++)if(!job->loan.parts[i]){
        if(job->loan.sizes[i]>SIZE_MAX-missing)goto done;
        missing+=job->loan.sizes[i];
    }
    if(missing){
        workspace=wendy_pki_input_workspace_borrow(&capacity);
        workspace_borrowed=workspace!=NULL;
        if(workspace && capacity<missing){wendy_pki_input_workspace_release(workspace);workspace=NULL;workspace_borrowed=false;}
        if(!workspace){workspace=wendy_net_malloc(missing);capacity=missing;}
        if(!workspace)goto done;
        size_t used=0;
        for(unsigned i=0;i<job->loan.count;i++)if(!job->loan.parts[i]){
            job->loan.parts[i]=workspace+used;
            for(size_t at=0;at<job->loan.sizes[i];at+=WNCF_CHUNK){
                size_t total=0,wanted=job->loan.sizes[i]-at;if(wanted>WNCF_CHUNK)wanted=WNCF_CHUNK;
                int n=wendy_pki_mesh_local_part(&job->clock,job->chain.hashes[i],at,workspace+used+at,&total);
                if(n!=(int)wanted || total!=job->loan.sizes[i])goto done;
            }
            used+=job->loan.sizes[i];
        }
    }
    /* The actor pinned resident RAM entries before submission. Common local
     * issuers use the independently checked baseline reader and shared workspace;
     * no store/node/session address crosses this task boundary. */
#if CONFIG_WENDY_NET_TEST_DIAGNOSTICS
    size_t bytes=0;for(unsigned i=0;i<job->chain.count;i++)bytes+=job->loan.sizes[i];
    ESP_LOGI("net-cert-worker","public chain RAM: DER=%u cached=%u local=%u workspace=%u shared=%u free=%u largest=%u",
        (unsigned)bytes,(unsigned)(bytes-missing),(unsigned)missing,(unsigned)(workspace ? capacity:0),
        (unsigned)workspace_borrowed,(unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT),
        (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
#endif
    if(wn_principal_device(job->chain.principal,job->clock.tenant,device) ||
       wendy_pki_mesh_verify_snapshot(&job->clock,job->loan.parts,
           job->loan.sizes,job->chain.count,&job->peer) ||
       strcmp(job->peer.device,job->chain.principal+69))goto done;
    job->result=0;
done:
    if(workspace_borrowed)wendy_pki_input_workspace_release(workspace);
    else wendy_net_free(workspace);
    wncs_unpin(&job->loan);
    atomic_store(&job->done,true);wncv_release(job);
}
int wncv_start(struct wncv_job **out,struct wncs_store *store,const struct wncf_chain *chain,
                const struct wendy_pki_mesh_identity *clock)
{
    if(!out || *out || !store || !chain || !clock || !chain->count || chain->count>WNCF_CHAIN_MAX)return -1;
    wendy_net_memory_snapshot_t memory;wendy_net_runtime_memory_snapshot(&memory);
    if(!memory.external_enabled && wendy_pki_handshake_busy())return 1;
    struct wncv_job *job=wendy_net_calloc(1,sizeof *job);if(!job)return 1;
    job->chain=*chain;job->clock=*clock;atomic_init(&job->references,2);atomic_init(&job->done,false);
    /* On SRAM-only devices the heavy workspace stays exclusive across TLS I/O
     * waits too. A paused handshake still retains its parsed chain/buffers. */
    if(!memory.external_enabled){
        if(!wendy_pki_handshake_claim(job)){wendy_net_free(job);return 1;}
        job->workspace_owned=true;
    }
    if(wncs_pin_chain(store,chain,&job->loan)){
        atomic_store(&job->references,1);wncv_release(job);return 1;
    }
    if(!wendy_pki_work_submit(verify,job)){
        atomic_store(&job->references,1);wncv_release(job);return 1;
    }
    *out=job;return 0;
}
