/* Compose production native flow/BIO + real PQC TLS + actual WendyCom backend.
 * Existing TLS fixture utilities provide normal generated identity material;
 * only the NVS/configuration facade is replaced, never TLS/auth/protocol code. */
#define main ordinary_tls_fixture_main
#include "tls_test.c"
#undef main
#include "native_tls_fixture.h"
#include "wendy_operator_auth.h"
#include "wendy_net_alloc.h"
#include <psa/crypto_extra.h>
#include "../../wendy_net_peer/src/native_agent.c"
enum wcom_link_permission composed_expected_permission;
void composed_com_init(void);
void composed_com_poll(void);
void composed_com_check(void);
static struct pki_tls_owned_identity prepared;
static struct wendy_conf_span prepared_roots;
static uint64_t fixture_generation=1;
static unsigned outer_reads,outer_writes,outer_wakes,independent_io;
struct wendy_pki_agent_setup {wendy_pki_connection *connection;bool complete;};
bool wendy_conf_is_current(void){return true;}
bool wendy_conf_snapshot_current(uint64_t generation){return generation==fixture_generation;}
void wnad_wake(void){outer_wakes++;}
bool wnad_handshake_claim(void *owner){return wendy_pki_handshake_claim(owner);}
void wnad_handshake_release(void *owner){wendy_pki_handshake_release(owner);}
int wnad_no_wait(void *context,bool writing,int64_t deadline){assert(0);return -1;}
esp_err_t wendy_pki_agent_begin(const struct wendy_pki_stream *bio,struct wendy_pki_agent_setup **out)
{
    struct wendy_pki_agent_setup *op=pki_owned_calloc(1,sizeof *op);assert(op);
    prepared.input_reserve=26624;prepared.reserve_records_first=true;
    prepared.input_reservation=mbedtls_calloc(1,prepared.input_reserve);assert(prepared.input_reservation);
    int result=pki_tls_agent_begin(bio,"2558fd76-afc7-466e-9613-6b715296a526",
        "00000000-0000-4000-8000-000000000004",&prepared,prepared_roots,&op->connection);
    if(result){pki_owned_free(op);return ESP_FAIL;}
    *out=op;return ESP_OK;
}
int wendy_pki_agent_step(struct wendy_pki_agent_setup *op)
{
    int result=pki_tls_agent_advance(op->connection);if(!result)op->complete=true;
    return result;
}
wendy_pki_connection *wendy_pki_agent_take(struct wendy_pki_agent_setup *op,struct wendy_pki_agent_info *info)
{
    assert(op->complete);wendy_pki_connection *connection=op->connection;
    *info=(struct wendy_pki_agent_info){.role=connection->peer_role,.config_generation=fixture_generation,
        .session_deadline_us=connection->session_deadline_us};
    pki_owned_free(op);return connection;
}
void wendy_pki_agent_dispose(struct wendy_pki_agent_setup *op)
{if(op){wendy_pki_close(op->connection);pki_owned_free(op);}}
int wnad_channel_io(struct wna_channel *channel,int fd,const struct wendy_pki_stream *stream)
{
    assert(!stream);int progress=0;
    if(channel->output.size){
        size_t size=channel->output.size;if(size>17)size=17;
        ssize_t n=send(fd,channel->output.bytes+channel->output.offset,size,MSG_DONTWAIT);
        if(n>0){wna_buffer_consume(&channel->output,(size_t)n);outer_writes++;progress=1;}
        else assert(errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR);
    }
    size_t room=wna_buffer_space(&channel->input);if(room>31)room=31;
    if(room && !channel->eof){
        ssize_t n=recv(fd,channel->input.bytes+channel->input.size,room,MSG_DONTWAIT);
        if(n>0){channel->input.size+=(size_t)n;outer_reads++;progress=1;}
        else if(!n){channel->eof=true;progress=1;}
        else assert(errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR);
    }
    return progress;
}
int main(int argc,char **argv)
{
    if(argc!=5 || strncmp(argv[4],"owned-lan-",10)){
        unsetenv("WENDY_TLS_DEFER_INPUT_SHRINK");return ordinary_tls_fixture_main(argc,argv);
    }
    assert(getenv("WENDY_TLS_NORMAL_ONLY") && getenv("WENDY_TLS_AGENT_COMPOSED"));
    composed_expected_permission=!strcmp(getenv("WENDY_TLS_EXPECT_ROLE"),"operator") ? WCOM_LINK_PERMISSION_FULL:WCOM_LINK_PERMISSION_SENSOR_ONLY;
    assert(wendy_net_runtime_memory_open());
    assert(!mbedtls_platform_set_calloc_free(wendy_net_memory_scoped_calloc,wendy_net_memory_scoped_free));
    assert(mbedtls_psa_set_key_slot_table_allocator(wendy_pki_crypto_shared_calloc)==PSA_SUCCESS);
    assert(!wendy_pki_crypto_init()); /* permanent baseline PSA initialization */
    size_t key_size,cert_size,roots_size;
    uint8_t *key=load(argv[1],&key_size),*cert=load(argv[2],&cert_size),*roots=load(argv[3],&roots_size);
    size_t der_size=0;assert(!wendy_cert_bundle_measure(roots,roots_size,&der_size));
    uint8_t *der_roots=calloc(1,der_size+1);assert(der_roots);
    assert(!wendy_cert_bundle_import(roots,roots_size,der_roots,der_size,&der_size));
    free(roots);roots=der_roots;roots_size=der_size;
    struct der_source_test source={0};mbedtls_x509_crt_init(&source.chain);
    assert(!pki_parse_certificate_bundle(&source.chain,cert,cert_size,false));free(cert);
    prepared=(struct pki_tls_owned_identity){.key=key,.key_size=key_size,.trust=roots,.trust_capacity=roots_size+1,
        .verify_at=time(NULL),.read_der=read_der_test,.hash_der=hash_der_test,.read_der_range=read_der_range_test,.der_context=&source};
    prepared_roots=(struct wendy_conf_span){roots,roots_size};
    composed_com_init();wendy_pki_work_enable();
    int listener=socket(AF_INET,SOCK_STREAM,0);assert(listener>=0);
    struct sockaddr_in address={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    assert(!bind(listener,(struct sockaddr *)&address,sizeof address));socklen_t size=sizeof address;
    assert(!getsockname(listener,(struct sockaddr *)&address,&size));assert(!listen(listener,1));
    printf("%u\n",(unsigned)ntohs(address.sin_port));fflush(stdout);
    int fd=accept(listener,NULL,NULL);assert(fd>=0);close(listener);
    int readiness[2];assert(!socketpair(AF_UNIX,SOCK_STREAM,0,readiness));
    wendy_net_memory_scope_t previous=wendy_net_runtime_scope_enter();
    wendy_net_agent_start();wendy_net_agent_accept(fd);
    int64_t deadline=esp_timer_get_time()+30000000;
    bool authenticated=false,saw_eof=false;
    while(esp_timer_get_time()<deadline){
        int progress=wendy_net_agent_poll();
        if(flows && flows->state.lent){
            /* Independent ready I/O is still serviced before collecting this
             * specific TLS loan; this is queued-loan progress, not a host CPU
             * preemption benchmark or a complete carrier-gossip simulation. */
            uint8_t byte=42;assert(send(readiness[0],&byte,1,0)==1);
            assert(recv(readiness[1],&byte,1,0)==1 && byte==42);independent_io++;
        }
        bool worked=wendy_pki_work_poll();
        composed_com_poll();
        if(flows && flows->connection)authenticated=true;
        if(flows && flows->input_eof){saw_eof=true;break;}
        if(!flows && authenticated)break;
        if(!progress && !worked){struct pollfd pending={.fd=fd,.events=POLLIN|POLLOUT};(void)poll(&pending,1,1);}
    }
    assert(authenticated && saw_eof);composed_com_check();
    /* Hold the com application owner deliberately while OFF drains its TLS
     * CPU loan. Its queued close ACK must retain the admission/buffer leases. */
    assert(!wendy_net_agent_stop());
    for(unsigned i=0;i<3;i++){
        (void)wendy_pki_work_poll();assert(!wendy_net_agent_stop());
        assert(flows && flow_count==1 && wnab_live()==1);
    }
    bool stopped=false;
    for(unsigned i=0;i<30 && !stopped;i++){
        composed_com_poll();(void)wendy_pki_work_poll();stopped=wendy_net_agent_stop();
    }
    assert(stopped && !flows && !wnab_live());
    close(readiness[0]);close(readiness[1]);
    wendy_net_memory_snapshot_t memory;wendy_net_runtime_memory_snapshot(&memory);
    if(memory.current_bytes)fprintf(stderr,"COMPOSED outstanding: bytes=%zu allocations=%zu reservations=%zu\n",
        memory.current_bytes,memory.allocation_count,memory.reservation_count);
    assert(!memory.current_bytes && !memory.allocation_count && !memory.reservation_count);
    assert(outer_reads>1 && outer_writes>1 && outer_wakes && independent_io);
    wendy_net_memory_scope_leave(previous);wendy_net_runtime_memory_close();
    assert(wendy_net_runtime_memory_drained());mbedtls_x509_crt_free(&source.chain);
    fprintf(stderr,"COMPOSED native TLS/WendyCom: role=%u reads=%u writes=%u independent_io=%u peak=%zu OFF=0 PASS\n",
        composed_expected_permission,outer_reads,outer_writes,independent_io,memory.high_water_bytes);
    return 0;
}
