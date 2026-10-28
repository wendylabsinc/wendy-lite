/* Positive byte-stream integration: three real TLS contexts, fair carrier
 * framing, finite memory BIOs and one exclusively loaned handshake context. */
#define main ordinary_tls_fixture_main
#include "tls_test.c"
#undef main
#include "native_tls_fixture.h"
#include "wendy_pki_work.h"
#include "tls_agent_bio.h"
#include "wendy_net_carrier.h"
#include "wendy_net_peer_protocol.h"
#include "wendy_net_alloc.h"
#include <psa/crypto.h>
#include <psa/crypto_extra.h>
#include <stdatomic.h>
#include <pthread.h>
#include <sched.h>

#define PEERS 3
#define ROUNDS 24
#define ROUTE_BYTES 80
#define META_BYTES 1024
#define IP_BYTES 1100
struct endpoint {
    unsigned index,produced[3],received[3],io_calls,blocked,wants,retries;
    struct agent_bio bio;
    struct der_source_test source;
    struct wna_session state;
    wendy_pki_connection *tls;
    struct wnc_carrier carrier;
    uint8_t scratch[WN_DATAGRAM_MAX];
    psa_hash_operation_t sent,got;
    const void *retry;size_t retry_size;
    atomic_bool done;int result;
    bool prepared,ready,finished,hold_used;
};
static uint8_t *key_material,*cert_material,*root_material;
static size_t key_size,cert_size,root_size;
static uint8_t *copy_material(const uint8_t *bytes,size_t size)
{uint8_t *copy=calloc(1,size+1);assert(copy);memcpy(copy,bytes,size);return copy;}
static uint64_t other_progress,loan_progress,concurrent_records;
static unsigned held_turns,held_jobs;
static atomic_bool cpu_stop,cpu_allowed,cpu_running;
static pthread_mutex_t cpu_gate=PTHREAD_MUTEX_INITIALIZER;
static void *cpu_thread(void *unused)
{
    (void)unused;
    while(!atomic_load(&cpu_stop)){
        pthread_mutex_lock(&cpu_gate);
        if(atomic_load(&cpu_allowed))(void)wendy_pki_work_poll();
        pthread_mutex_unlock(&cpu_gate);sched_yield();
    }
    return NULL;
}
static size_t payload_size(unsigned category)
{return category==0 ? ROUTE_BYTES:category==1 ? META_BYTES:IP_BYTES;}
static void payload(uint8_t *out,unsigned category,unsigned peer,unsigned direction,unsigned sequence)
{
    size_t size=payload_size(category);
    out[0]=(uint8_t)(category==0 ? 2:category==1 ? 'M':1);
    out[1]=(uint8_t)peer;out[2]=(uint8_t)direction;out[3]=(uint8_t)sequence;
    for(size_t at=4;at<size;at++)out[at]=(uint8_t)(at*29+peer*61+direction*17+sequence*13+category*7);
}
static int no_wait(void *context,bool writing,int64_t deadline)
{(void)context;(void)writing;(void)deadline;assert(!"CPU effect cannot wait on I/O");return -1;}
static void cpu(void *context)
{
    struct endpoint *e=context;assert(e->state.lent && wendy_pki_work_is_current());
    atomic_store(&cpu_running,true);
    if(!e->prepared){
        size_t kn=key_size,cn=cert_size,rn=root_size;
        uint8_t *key=copy_material(key_material,kn),*cert=copy_material(cert_material,cn),*root=copy_material(root_material,rn);
        size_t der_size=0;assert(!wendy_cert_bundle_measure(root,rn,&der_size));
        uint8_t *der=calloc(1,der_size+1);assert(der);
        assert(!wendy_cert_bundle_import(root,rn,der,der_size,&der_size));free(root);root=der;rn=der_size;
        mbedtls_x509_crt_init(&e->source.chain);
        assert(!pki_parse_certificate_bundle(&e->source.chain,cert,cn,false));free(cert);
        struct pki_tls_owned_identity own={.key=key,.key_size=kn,
            .trust=root,.trust_capacity=rn+1,.verify_at=time(NULL),
            .read_der=read_der_test,.hash_der=hash_der_test,.read_der_range=read_der_range_test,
            .der_context=&e->source,.reserve_records_first=true,.input_reserve=26624};
        own.input_reservation=mbedtls_calloc(1,own.input_reserve);assert(own.input_reservation);
        struct wendy_pki_stream stream={.context=&e->bio.channel,.read=wna_read,.write=wna_write,.wait=no_wait};
        e->result=pki_tls_agent_begin(&stream,"2558fd76-afc7-466e-9613-6b715296a526",
            "00000000-0000-4000-8000-000000000004",&own,(struct wendy_conf_span){root,rn},&e->tls);
        e->prepared=e->result==0;
    }else e->result=pki_tls_agent_advance(e->tls);
    atomic_store(&cpu_running,false);atomic_store_explicit(&e->done,true,memory_order_release);
}
static void outer_io(struct endpoint *e)
{
    assert(!e->state.lent);e->io_calls++;
    /* Finite ordinary receiver pressure, independently phased per context. */
    if((e->io_calls+e->index)%7==0){e->blocked++;return;}
    unsigned before=e->bio.reads+e->bio.writes;
    (void)agent_bio_pump(&e->bio);
    if(e->index<2)other_progress+=e->bio.reads+e->bio.writes-before;
}
static ssize_t tls_read(void *context,void *bytes,size_t size)
{
    struct endpoint *e=context;assert(!e->state.lent);
    ssize_t n=wendy_pki_read(e->tls,bytes,size);
    if(atomic_load(&cpu_running))concurrent_records++;
    if(n>0)assert(!psa_hash_update(&e->got,bytes,(size_t)n));
    return n;
}
static ssize_t tls_write(void *context,const void *bytes,size_t size)
{
    struct endpoint *e=context;assert(!e->state.lent);
    if(e->retry){assert(e->retry==bytes && e->retry_size==size);e->retries++;}
    ssize_t n=wendy_pki_write(e->tls,bytes,size);
    if(atomic_load(&cpu_running))concurrent_records++;
    if(n==-2 || n==-3){e->retry=bytes;e->retry_size=size;e->wants++;}
    else{assert(n>0);assert(!psa_hash_update(&e->sent,bytes,(size_t)n));e->retry=NULL;e->retry_size=0;}
    return n;
}
static int frame(void *context,const void *bytes,size_t size,bool control)
{
    struct endpoint *e=context;const uint8_t *p=bytes;
    assert(size>=4 && p[1]==e->index && p[2]==1);
    unsigned category=control ? 1:p[0]==2 ? 0:2;
    assert(size==payload_size(category) && e->received[category]<ROUNDS);
    uint8_t expected[IP_BYTES];payload(expected,category,e->index,1,e->received[category]);
    assert(!memcmp(bytes,expected,size));e->received[category]++;return 0;
}
static void produce(struct endpoint *e)
{
    uint8_t bytes[IP_BYTES];
    for(unsigned k=0;k<3;k++)while(e->produced[k]<ROUNDS){
        payload(bytes,k,e->index,0,e->produced[k]);
        int r=k==2 ? wnc_enqueue(&e->carrier,bytes,payload_size(k),false):
            wnc_enqueue_priority(&e->carrier,bytes,payload_size(k),k==1);
        if(r){assert(r==WNC_LIMIT);break;}e->produced[k]++;
    }
}
static bool complete(const struct endpoint *e)
{
    if(!e->ready || e->carrier.queued || e->bio.channel.output.size)return false;
    for(unsigned k=0;k<3;k++)if(e->produced[k]!=ROUNDS || e->received[k]!=ROUNDS)return false;
    return true;
}
static void print_hash(const uint8_t bytes[32])
{for(unsigned i=0;i<32;i++)printf("%02x",bytes[i]);}
int main(int argc,char **argv)
{
    assert(argc==4);
    /* Fixture file I/O precedes the actor/CPU driver; worker effects receive
     * immutable bytes and memory BIOs, never socket/file read callbacks. */
    key_material=load(argv[1],&key_size);cert_material=load(argv[2],&cert_size);root_material=load(argv[3],&root_size);
    assert(!mbedtls_platform_set_calloc_free(wendy_net_memory_scoped_calloc,wendy_net_memory_scoped_free));
    assert(mbedtls_psa_set_key_slot_table_allocator(wendy_pki_crypto_shared_calloc)==PSA_SUCCESS);
    assert(!wendy_pki_crypto_init());
    assert(wendy_net_memory_open(wendy_net_runtime_memory_ledger(),2*1024*1024,true));
    wendy_net_memory_scope_t previous=wendy_net_runtime_scope_enter();wendy_pki_work_enable();
    int listener=socket(AF_INET,SOCK_STREAM,0);assert(listener>=0);struct sockaddr_in address={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    assert(!bind(listener,(struct sockaddr*)&address,sizeof address));socklen_t n=sizeof address;
    assert(!getsockname(listener,(struct sockaddr*)&address,&n));assert(!listen(listener,3));printf("%u\n",(unsigned)ntohs(address.sin_port));fflush(stdout);
    struct endpoint *peers=calloc(PEERS,sizeof *peers);assert(peers);
    for(unsigned i=0;i<PEERS;i++){
        struct endpoint *e=&peers[i];e->index=i;e->bio.fd=accept(listener,NULL,NULL);assert(e->bio.fd>=0);
        assert(!fcntl(e->bio.fd,F_SETFL,O_NONBLOCK));e->state.deadline=UINT64_MAX;
        struct wnc_io io={e,tls_read,tls_write};assert(!wnc_init(&e->carrier,&io,e->scratch,sizeof e->scratch,8192,2048));
        assert(!wnc_fair_scheduler(&e->carrier,8));e->sent=psa_hash_operation_init();e->got=psa_hash_operation_init();
        assert(!psa_hash_setup(&e->sent,PSA_ALG_SHA_256));assert(!psa_hash_setup(&e->got,PSA_ALG_SHA_256));
    }
    close(listener);atomic_store(&cpu_allowed,true);pthread_t worker;assert(!pthread_create(&worker,NULL,cpu_thread,NULL));
    unsigned finished=0,hold=0;uint64_t start_progress=0;int64_t deadline=esp_timer_get_time()+30000000;
    while(finished<PEERS && esp_timer_get_time()<deadline){
        for(unsigned i=0;i<PEERS;i++){
            struct endpoint *e=&peers[i];if(e->finished)continue;
            if(e->state.lent){
                if(!atomic_load_explicit(&e->done,memory_order_acquire))continue;
                wna_completed(&e->state,e->result);assert(e->result==0 || e->result==1 || e->result==-2 || e->result==-3);
                if(e->state.phase==WNA_READY){e->ready=true;assert(e->tls->peer_role==WENDY_PEER_ROLE_DEVICE);}
            }
            outer_io(e);
            if(!e->ready){
                if(i==2 && (!peers[0].ready || !peers[1].ready))continue;
                enum wna_effect effect=wna_next(&e->state,0,e->bio.channel.input.size!=0,wna_buffer_space(&e->bio.channel.output)!=0);
                if((effect==WNA_CRYPTO_PREPARE || effect==WNA_CRYPTO_STEP) && wendy_pki_work_idle()){
                    bool delayed=i==2 && e->prepared && !e->hold_used;
                    if(delayed && pthread_mutex_trylock(&cpu_gate))continue;
                    if(delayed)atomic_store(&cpu_allowed,false);
                    atomic_store(&e->done,false);wna_lend(&e->state);assert(wendy_pki_work_submit(cpu,e));
                    if(delayed){e->hold_used=true;hold=256;start_progress=other_progress;held_jobs++;pthread_mutex_unlock(&cpu_gate);}
                }
            }else{
                produce(e);int pumped=wnc_pump(&e->carrier,1000000,frame,e);assert(pumped>=0);
                if(complete(e)){e->finished=true;finished++;}
            }
        }
        if(hold){held_turns++;if(!--hold){loan_progress+=other_progress-start_progress;assert(loan_progress);atomic_store(&cpu_allowed,true);}}
        sched_yield();
    }
    assert(finished==PEERS && held_jobs==1 && held_turns==256 && loan_progress);
    atomic_store(&cpu_stop,true);assert(!pthread_join(worker,NULL));
    for(unsigned i=0;i<PEERS;i++){
        struct endpoint *e=&peers[i];assert(!e->state.lent && !e->retry && e->wants && e->retries && e->blocked);
        uint8_t sent[32],got[32];size_t hashed;assert(!psa_hash_finish(&e->sent,sent,sizeof sent,&hashed) && hashed==32);assert(!psa_hash_finish(&e->got,got,sizeof got,&hashed) && hashed==32);
        printf("{\"peer\":%u,\"sent\":\"",i);print_hash(sent);printf("\",\"got\":\"");print_hash(got);
        printf("\",\"wants\":%u,\"retries\":%u,\"loanProgress\":%llu}\n",e->wants,e->retries,(unsigned long long)loan_progress);fflush(stdout);
        wnc_deinit(&e->carrier);wendy_pki_close(e->tls);mbedtls_x509_crt_free(&e->source.chain);close(e->bio.fd);assert(!psa_hash_abort(&e->sent));assert(!psa_hash_abort(&e->got));
    }
    free(peers);free(key_material);free(cert_material);free(root_material);wendy_net_memory_snapshot_t memory;wendy_net_runtime_memory_snapshot(&memory);
    assert(!memory.current_bytes);wendy_net_memory_scope_leave(previous);wendy_net_runtime_memory_close();assert(wendy_net_runtime_memory_drained());
    fprintf(stderr,"Three-context fair carrier/TLS exact-byte/loan test PASS; peak=%zu BIO=%u queued_loan_io=%llu record_calls_during_cpu=%llu\n",memory.high_water_bytes,WNA_IO_BYTES,(unsigned long long)loan_progress,(unsigned long long)concurrent_records);return 0;
}
