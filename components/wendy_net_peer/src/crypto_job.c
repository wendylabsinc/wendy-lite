#include "crypto_job.h"
#include "wendy_net_alloc.h"
#include "wendy_pki_work.h"
#include "wendy_pki_crypto.h"
#include "wendy_pki_hash.h"
#include <psa/crypto.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
struct wncrypto_job {
    atomic_uint refs;
    atomic_bool done;
    unsigned kind;
    bool signing,workspace_owned;
    int result;
    wendy_pki_connection *connection;
    struct wendy_pki_mesh_key key;
    char principal[106];
    uint8_t fingerprint[32],digest[32];
    size_t size,signature_size,signature_capacity;
    uint8_t *signature;
    const uint8_t *verification_signature;
    uint8_t *data;
};
/* Actor-owned list of signing loans, bounded by accepted protocol operations.
 * The worker never traverses it or mutates connection ownership. */
struct signing_loan {struct signing_loan *next;struct wncrypto_job *job;bool orphan;};
static struct signing_loan *loans;
static bool workspace_claim(struct wncrypto_job *job)
{
#if ESP_PLATFORM || defined(WENDY_NET_ROUTE_CRYPTO_HOST_TEST)
    wendy_net_memory_snapshot_t memory;wendy_net_runtime_memory_snapshot(&memory);
    if(!memory.external_enabled){
        if(!wendy_pki_handshake_claim(job))return false;
        job->workspace_owned=true;
    }
#else
    (void)job;
#endif
    return true;
}
static void release_inputs(struct wncrypto_job *j)
{
    wendy_net_free(j->data);j->data=NULL;j->key.spki=NULL;j->verification_signature=NULL;
#if ESP_PLATFORM || defined(WENDY_NET_ROUTE_CRYPTO_HOST_TEST)
    /* Exact input digests now replace byte comparisons at completion. The
     * worker can destroy every large copy and its gate BEFORE publishing done,
     * rather than depend on the actor finding room for another parser first. */
    if(j->workspace_owned){wendy_pki_handshake_release(j);j->workspace_owned=false;}
#endif
}
static void release(struct wncrypto_job *j)
{
    if(atomic_fetch_sub(&j->refs,1)==1){
        release_inputs(j);
        wendy_net_free(j->signature);
        wendy_net_free(j);
    }
}
static void discard_unsubmitted(struct wncrypto_job *job)
{
    /* No other owner has seen this job; use the same ordered destruction. */
    atomic_store(&job->refs,1);release(job);
}
static void execute(void *context)
{
    struct wncrypto_job *j=context;
    if(j->signing){
        j->signature=wendy_net_malloc(j->signature_capacity);
        if(!j->signature)j->result=1;
        else j->result=j->signature_capacity==80 ?
            wendy_pki_mesh_sign_digest(j->connection,j->principal,j->digest,j->signature,&j->signature_size):
            wendy_pki_artifact_sign(j->connection,j->kind,j->principal,j->data,j->size,
                j->signature,j->signature_capacity,&j->signature_size);
        if(j->result){wendy_net_free(j->signature);j->signature=NULL;j->signature_size=0;}
    }else j->result=wendy_pki_mesh_verify_key(&j->key,j->principal,j->data,j->size,j->verification_signature,j->signature_size);
    release_inputs(j);atomic_store(&j->done,true);release(j);
}
static void remove_loan(struct wncrypto_job *j)
{
    for(struct signing_loan **at=&loans;*at;at=&(*at)->next)
        if((*at)->job==j){struct signing_loan *old=*at;*at=old->next;wendy_net_free(old);return;}
}
bool wncrypto_take_verification(struct wncrypto_job **slot,struct wncrypto_verdict *out)
{
    struct wncrypto_job *j=slot ? *slot:NULL;
    if(!j || !out || j->signing || !atomic_load(&j->done))return false;
    *out=(struct wncrypto_verdict){.result=j->result,.kind=j->kind,.valid=true};
    memcpy(out->input,j->digest,32);
    *slot=NULL;release(j);return true;
}
bool wncrypto_take_signature(struct wncrypto_job **slot,struct wncrypto_signature *out)
{
    struct wncrypto_job *j=slot ? *slot:NULL;
    if(!j || !out || !j->signing || !atomic_load(&j->done))return false;
    wncrypto_signature_clear(out);
    *out=(struct wncrypto_signature){.result=j->result,.kind=j->kind,
        .connection=j->connection,.signature=j->signature,.signature_size=j->signature_size,.valid=true};
    j->signature=NULL;
    memcpy(out->digest,j->digest,32);memcpy(out->fingerprint,j->fingerprint,32);
    remove_loan(j);*slot=NULL;release(j);return true;
}
void wncrypto_cancel(struct wncrypto_job **slot)
{
    struct wncrypto_job *j=*slot;if(!j)return;
    /* A signing connection is not torn down while a loan is outstanding.
     * Verification jobs own all input and can outlive their protocol owner. */
    if(j->signing && !atomic_load(&j->done)){
        for(struct signing_loan *l=loans;l;l=l->next)if(l->job==j)l->orphan=true;
        *slot=NULL;return; /* Loan owns the remaining actor reference. */
    }
    remove_loan(j);*slot=NULL;release(j);
}
bool wncrypto_borrowed(wendy_pki_connection *c)
{
    for(struct signing_loan **at=&loans;*at;){
        struct signing_loan *l=*at;
        if(l->orphan && atomic_load(&l->job->done)){*at=l->next;release(l->job);wendy_net_free(l);continue;}
        if(l->job->connection==c && !atomic_load(&l->job->done))return true;
        at=&l->next;
    }
    return false;
}
static struct wncrypto_job *allocate(unsigned kind,const char *principal,const void *body,size_t size,
    const uint8_t *signature,size_t signature_size,const struct wendy_pki_mesh_key *key,bool needs_workspace)
{
    if(kind!=0 || size>40*1024 || signature_size>WENDY_PKI_MESH_SIGNATURE_MAX || !principal || strlen(principal)!=105)return NULL;
    size_t spki=key ? key->spki_size:0;
    if(spki>WENDY_PKI_MESH_SPKI_MAX)return NULL;
    struct wncrypto_job *j=wendy_net_calloc(1,sizeof *j);if(!j)return NULL;
    atomic_init(&j->refs,2);
    /* Claim with only the small stable header allocated. A blocked handshake
     * must not briefly overlap a40KiB immutable copy on an SRAM-only target. */
    if(needs_workspace && !workspace_claim(j)){discard_unsubmitted(j);return NULL;}
    size_t bytes=size+spki+signature_size;
    if(bytes && !(j->data=wendy_net_malloc(bytes))){discard_unsubmitted(j);return NULL;}
    j->kind=kind;j->size=size;memcpy(j->principal,principal,106);
    if(size)memcpy(j->data,body,size);
    j->signature_size=signature_size;
    if(signature_size){j->verification_signature=j->data+size+spki;memcpy((void *)j->verification_signature,signature,signature_size);}
    if(key){j->key=*key;j->key.spki=j->data+size;memcpy(j->data+size,key->spki,spki);}
    return j;
}
static int verification_digest(unsigned kind,const struct wendy_pki_mesh_key *key,const char *principal,
    const void *body,size_t size,const uint8_t *signature,size_t signature_size,uint8_t digest[32])
{
    static const uint8_t domain[]="wendy-net/crypto-completion/1";
    if(kind!=0 || !key || !key->spki || !key->spki_size || key->spki_size>WENDY_PKI_MESH_SPKI_MAX ||
       !principal || strlen(principal)!=105 || !body || !size || size>40*1024 || !signature ||
       !signature_size || signature_size>WENDY_PKI_MESH_SIGNATURE_MAX || wendy_pki_crypto_init())return -1;
    uint8_t header[17];header[0]=(uint8_t)kind;
    for(unsigned i=0;i<8;i++){header[8-i]=(uint8_t)((uint64_t)size>>(8*i));header[16-i]=(uint8_t)((uint64_t)signature_size>>(8*i));}
    psa_hash_operation_t operation=PSA_HASH_OPERATION_INIT;size_t written=0;
    bool okay=psa_hash_setup(&operation,PSA_ALG_SHA_256)==PSA_SUCCESS &&
        wendy_pki_hash_update_bounded(&operation,domain,sizeof domain)==PSA_SUCCESS &&
        wendy_pki_hash_update_bounded(&operation,header,sizeof header)==PSA_SUCCESS &&
        wendy_pki_hash_update_bounded(&operation,(const uint8_t*)principal,105)==PSA_SUCCESS &&
        wendy_pki_hash_update_bounded(&operation,body,size)==PSA_SUCCESS &&
        wendy_pki_hash_update_bounded(&operation,signature,signature_size)==PSA_SUCCESS &&
        wendy_pki_hash_update_bounded(&operation,key->spki,key->spki_size)==PSA_SUCCESS &&
        psa_hash_finish(&operation,digest,32,&written)==PSA_SUCCESS && written==32;
    psa_hash_abort(&operation);return okay ? 0:-1;
}
int wncrypto_sign_cached(struct wncrypto_job **slot,struct wncrypto_signature *completed,
    unsigned kind,wendy_pki_connection *c,const char *principal,
    const void *body,size_t size,const uint8_t **signature,size_t *written)
{
    if(!slot || !completed || !signature || !written || kind!=0)return -1;
    *signature=NULL;*written=0;
    (void)wncrypto_take_signature(slot,completed);
    if(*slot || wncrypto_borrowed(c))return 1;
    size_t capacity=wendy_pki_artifact_signature_capacity(c);
    if(!capacity || capacity>WENDY_PKI_MESH_SIGNATURE_MAX){wncrypto_signature_clear(completed);return -1;}
    uint8_t digest[32];
    int hashed=wendy_pki_mesh_digest(principal,body,size,digest);
    if(hashed)return completed->valid ? 1:-1;
    if(completed->valid){
        uint8_t current[32];
        if(completed->kind!=kind || completed->connection!=c || memcmp(digest,completed->digest,32) ||
           wendy_pki_mesh_fingerprint(c,current) || memcmp(current,completed->fingerprint,32)){
            wncrypto_signature_clear(completed);
        }else if(completed->result>0){
            wncrypto_signature_clear(completed); /* No signing happened; retry same draft. */
        }else{
            int r=completed->result;
            if(!r && completed->signature && completed->signature_size){
                *signature=completed->signature;*written=completed->signature_size;
            }else r=-1;
            return r;
        }
    }
    if(!wendy_pki_work_idle())return 1;
    bool pure_message=capacity>80;
    /* A P256 signing job retains only a digest and signs on the same serial
     * worker. Reserving the entire TLS/MLDSA workspace for this small job can
     * stall the initial router proof behind an unrelated live handshake,
     * preventing control reads until the peer's write deadline expires. Pure
     * MLDSA messages and verification copies keep their exclusive admission. */
    struct wncrypto_job *j=allocate(kind,principal,pure_message ? body:NULL,pure_message ? size:0,NULL,0,NULL,pure_message);if(!j)return 1;
    j->signing=true;j->connection=c;j->signature_capacity=capacity;memcpy(j->digest,digest,32);
    if(wendy_pki_mesh_fingerprint(c,j->fingerprint)){discard_unsubmitted(j);return -1;}
    struct signing_loan *loan=wendy_net_malloc(sizeof *loan);if(!loan){discard_unsubmitted(j);return 1;}
    if(!wendy_pki_work_submit(execute,j)){
        wendy_net_free(loan);discard_unsubmitted(j);return 1;
    }
    loan->orphan=false;loan->job=j;loan->next=loans;loans=loan;*slot=j;return 1;
}
int wncrypto_verify_cached(struct wncrypto_job **slot,struct wncrypto_verdict *completed,
    unsigned kind,const struct wendy_pki_mesh_key *key,
    const char *principal,const void *body,size_t size,const uint8_t *signature,size_t signature_size)
{
    if(!slot || !completed)return -1;
    (void)wncrypto_take_verification(slot,completed);if(*slot)return 1;
    uint8_t digest[32];if(verification_digest(kind,key,principal,body,size,signature,signature_size,digest))return -1;
    if(completed->valid){
        if(completed->kind==kind && !memcmp(completed->input,digest,32))return completed->result ? -1:0;
        completed->valid=false;
    }
    if(!wendy_pki_work_idle())return 1;
    struct wncrypto_job *j=allocate(kind,principal,body,size,signature,signature_size,key,true);if(!j)return 1;
    memcpy(j->digest,digest,32);
    if(!wendy_pki_work_submit(execute,j)){
        discard_unsubmitted(j);return 1;
    }
    *slot=j;return 1;
}
int wncrypto_verify(struct wncrypto_job **slot,unsigned kind,const struct wendy_pki_mesh_key *key,
    const char *principal,const void *body,size_t size,const uint8_t *signature,size_t signature_size)
{
    struct wncrypto_verdict completed={0};
    return wncrypto_verify_cached(slot,&completed,kind,key,principal,body,size,signature,signature_size);
}

bool wncrypto_ready(const struct wncrypto_job *j){return j && atomic_load(&j->done);}
