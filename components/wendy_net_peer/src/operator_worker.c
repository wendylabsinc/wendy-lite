/* SPDX-License-Identifier: Apache-2.0 */
#include "operator_worker.h"
#include "wendy_net_alloc.h"
#include "wendy_pki_work.h"
#include <string.h>

void wnop_job_release(struct wnop_job *job)
{
    if(job && atomic_fetch_sub(&job->references,1)==1){
        wncs_unpin(&job->loan);wendy_net_free(job->peer);wendy_net_free(job->wire);
        if(job->workspace_owned)wendy_pki_handshake_release(job);
        wendy_net_free(job);
    }
}
static void execute(void *context)
{
    struct wnop_job *job=context;job->result=-1;
    uint8_t *workspace=NULL;size_t capacity=0;bool borrowed=false;
    wendy_net_memory_t *owner=wendy_net_memory_scope_current().owner;
    wendy_net_memory_snapshot_t before={0},after={0};
    if(owner)wendy_net_memory_snapshot(owner,&before);
    struct wno_manifest proof;
    if(!wendy_pki_operator_snapshot_current(&job->clock) ||
       wno_manifest_read(job->wire,job->size,job->clock.tenant,&proof))goto done;
    if(!job->cached){
        size_t missing=0;
        for(unsigned i=0;i<job->loan.count;i++)if(!job->loan.parts[i]){
            if(job->loan.sizes[i]>128*1024-missing)goto done;
            missing+=job->loan.sizes[i];
        }
        if(missing){
            workspace=wendy_pki_input_workspace_borrow(&capacity);borrowed=workspace!=NULL;
            if(workspace && capacity<missing){wendy_pki_input_workspace_release(workspace);workspace=NULL;borrowed=false;}
            if(!workspace){workspace=wendy_net_malloc(missing);capacity=missing;}
            if(!workspace){job->result=1;goto done;}
            size_t used=0;
            for(unsigned i=0;i<job->loan.count;i++)if(!job->loan.parts[i]){
                job->loan.parts[i]=workspace+used;
                for(size_t at=0;at<job->loan.sizes[i];at+=WNCF_CHUNK){
                    size_t total=0,wanted=job->loan.sizes[i]-at;if(wanted>WNCF_CHUNK)wanted=WNCF_CHUNK;
                    int n=wendy_pki_mesh_local_part(&job->clock,
                        job->hashes[i],at,workspace+used+at,&total);
                    if(n!=(int)wanted || total!=job->loan.sizes[i]){job->result=1;goto done;}
                }
                used+=job->loan.sizes[i];
            }
        }
        if(wendy_pki_operator_verify_snapshot(&job->clock,job->loan.parts,job->loan.sizes,job->loan.count,job->peer))goto done;
    }
    if(strlen(job->peer->principal)!=proof.principal_size || memcmp(job->peer->principal,proof.principal,proof.principal_size))goto done;
    job->result=wendy_pki_operator_manifest_verify(job->peer,proof.body,proof.body_size,proof.signature,proof.signature_size);
    if(!wendy_pki_operator_snapshot_current(&job->clock))job->result=-1;
done:
    /* PKI may report budget pressure as a generic verification error. Keep
     * the already completed download and retry, matching device proofs. */
    if(owner && job->result<0){
        wendy_net_memory_snapshot(owner,&after);
        if(after.failed_admissions!=before.failed_admissions)job->result=1;
    }
    if(borrowed)wendy_pki_input_workspace_release(workspace);else wendy_net_free(workspace);
    /* Release heavy inputs before publishing completion. The owner's cookie
     * stays alive until the actor observes it; no context/store crosses tasks. */
    wncs_unpin(&job->loan);
    wendy_net_free(job->wire);job->wire=NULL;
    atomic_store(&job->done,true);wnop_job_release(job);
}
int wnop_job_start(struct wnop_job **out,struct wncs_store *store,const void *wire,size_t size,
    const struct wendy_pki_mesh_identity *clock,const struct wnop_primary_key *cached)
{
    if(!out || *out || !store || !clock || !wire || !size || size>WNO_ARTIFACT_MAX)return -1;
    if(!wendy_pki_work_idle())return 1;
    struct wno_manifest proof;int parsed=wno_manifest_read(wire,size,clock->tenant,&proof);if(parsed)return -1;
    struct wnop_job *job=wendy_net_calloc(1,sizeof *job);if(!job)return 1;
    atomic_init(&job->references,1);atomic_init(&job->done,false);job->clock=*clock;
    wendy_net_memory_snapshot_t memory;wendy_net_runtime_memory_snapshot(&memory);
    if(!memory.external_enabled){
        if(!wendy_pki_handshake_claim(job)){wnop_job_release(job);return 1;}
        job->workspace_owned=true;
    }
    job->cached=cached!=NULL;
    for(unsigned i=0;i<proof.hash_count;i++)memcpy(job->hashes[i],proof.hashes[i],32);
    if(!cached){int pinned=wncs_pin_hashes(store,job->hashes,proof.hash_count,&job->loan);
        if(pinned){wnop_job_release(job);return pinned>0 ? 2:-1;}}
    job->wire=wendy_net_malloc(size);job->peer=wendy_net_calloc(1,sizeof *job->peer);
    if(!job->wire || !job->peer){wnop_job_release(job);return 1;}
    memcpy(job->wire,wire,size);job->size=size;
    if(cached){
        size_t n=cached->principal ? strlen(cached->principal):0;
        if(!n || n>WENDY_PKI_OPERATOR_PRINCIPAL_MAX || !cached->spki || !cached->spki_size || cached->spki_size>sizeof job->peer->spki){wnop_job_release(job);return -1;}
        if(!cached->leaf_hash){wnop_job_release(job);return -1;}
        memcpy(job->peer->leaf_hash,cached->leaf_hash,32);
        memcpy(job->peer->principal,cached->principal,n+1);job->peer->expires=cached->expires;
        memcpy(job->peer->spki,cached->spki,cached->spki_size);job->peer->spki_size=cached->spki_size;
    }
    atomic_fetch_add(&job->references,1);
    if(!wendy_pki_work_submit(execute,job)){
        atomic_fetch_sub(&job->references,1);wnop_job_release(job);return 1;
    }
    *out=job;return 0;
}
