/* Actual production app actor + TLS + WAS1 to an ordinary guest-owned port.
 * NVS provisioning and the guest endpoint are isolated fixture facades. */
#define main ordinary_tls_fixture_main
#include "tls_test.c"
#undef main
#include "native_tls_fixture.h"
#include "wendy_pki_work.h"
#include "wendy_net_alloc.h"
#include "../../wendy_net_peer/src/app.c"
static struct pki_tls_owned_identity prepared;
static struct wendy_conf_span prepared_roots;
static int guest_fd=-1;static uint8_t udp_payload[513];static bool reply_pending;
static unsigned completions,datagrams,sent_datagrams,discarded;
static uint64_t generation=17;
struct wendy_pki_net_setup{wendy_pki_connection *connection;bool complete;};
bool wendy_conf_is_current(void){return true;}
bool wendy_conf_snapshot_current(uint64_t value){return value==generation;}
void wendy_conf_get_enrolled_ids(char tenant[37],char device[65]){strcpy(tenant,"11111111-1111-4111-8111-111111111111");strcpy(device,"33333333-3333-4333-8333-333333333333");}
void wnad_wake(void){}
bool wnad_handshake_claim(void *owner){return wendy_pki_handshake_claim(owner);}
void wnad_handshake_release(void *owner){wendy_pki_handshake_release(owner);}
int wnad_no_wait(void *ctx,bool writing,int64_t deadline){assert(!"CPU effect waited for I/O");return -1;}
esp_err_t wendy_pki_net_begin(const struct wendy_pki_stream *bio,bool server,const char *expected,bool app,struct wendy_pki_net_setup **out)
{
 assert(server && app && !expected);struct wendy_pki_net_setup *op=pki_owned_calloc(1,sizeof *op);assert(op);
 int result=pki_tls_net_begin(bio,true,"11111111-1111-4111-8111-111111111111","33333333-3333-4333-8333-333333333333",&prepared,prepared_roots,true,&op->connection);
 if(result){pki_owned_free(op);return ESP_FAIL;}*out=op;return ESP_OK;
}
void wendy_net_peer_issuer_snapshot(struct wendy_pki_net_issuers *snapshot){memset(snapshot,0,sizeof *snapshot);}
void wendy_pki_net_add_issuers(struct wendy_pki_net_setup *op,struct wendy_pki_net_issuers *snapshot){pki_tls_net_add_issuers(op->connection,snapshot);}
int wendy_pki_net_step(struct wendy_pki_net_setup *op){int r=pki_tls_net_advance(op->connection,true,NULL);if(!r)op->complete=true;return r;}
wendy_pki_connection *wendy_pki_net_take(struct wendy_pki_net_setup *op,struct wendy_pki_mesh_identity *identity)
{assert(op->complete);identity->config_generation=generation;wendy_pki_connection *c=op->connection;pki_owned_free(op);return c;}
void wendy_pki_net_dispose(struct wendy_pki_net_setup *op){if(op){wendy_pki_close(op->connection);pki_owned_free(op);}}
int wnad_channel_io(struct wna_channel *c,int fd,const struct wendy_pki_stream *unused)
{
 int progress=0;if(c->output.size){size_t n=c->output.size;if(n>17)n=17;ssize_t sent=send(fd,c->output.bytes+c->output.offset,n,MSG_DONTWAIT);if(sent>0){wna_buffer_consume(&c->output,(size_t)sent);progress=1;}}
 size_t room=wna_buffer_space(&c->input);if(room>31)room=31;
 if(room && !c->eof){ssize_t n=recv(fd,c->input.bytes+c->input.size,room,MSG_DONTWAIT);if(n>0){c->input.size+=(size_t)n;progress=1;}else if(!n){c->eof=true;progress=1;}}
 return progress;
}
int wnad_connected(int fd){return 1;}
int wnad_connect(const char *host,unsigned port,bool *connecting){*connecting=false;return -1;}
static void pair(int fd[2]){assert(!socketpair(AF_UNIX,SOCK_STREAM,0,fd));for(unsigned i=0;i<2;i++)assert(!fcntl(fd[i],F_SETFL,O_NONBLOCK));}
int wendy_net_guest_service_begin(uint16_t port){assert(port==28000);int fd[2];pair(fd);guest_fd=fd[1];return fd[0];}
int wendy_net_guest_service_connect(uint16_t port){return -1;}
int wendy_net_guest_datagram_connect(uint16_t port,int *owner){return -1;}
int wendy_net_guest_datagram_owner(uint16_t port){return port==28001 ? 7:-1;}
unsigned wendy_net_guest_datagram_capacity(void){return 1024;}
bool wendy_net_mesh_socket_live(int handle){return true;}
int wendy_net_mesh_connected(int handle,int fd){assert(handle>0);completions++;if(fd>=0)close(fd);return 0;}
int wendy_net_mesh_datagram_connected(int handle,unsigned maximum){return 0;}
int wendy_net_guest_datagram_deliver_owned(int owner,int *association,uint8_t **packet,size_t size,unsigned maximum,wendy_net_packet_release_fn release)
{assert(owner==7 && size==sizeof udp_payload && !memcmp(*packet,udp_payload,size));*association=9;release(*packet);*packet=NULL;datagrams++;reply_pending=true;return 1;}
int wendy_net_mesh_datagram_receive_owned(int handle,uint8_t **packet,size_t size,wendy_net_packet_release_fn release){return -1;}
int wendy_net_guest_datagram_take(int handle,uint8_t **packet,size_t *size)
{if(!reply_pending)return 0;reply_pending=false;*size=sizeof udp_payload;*packet=malloc(*size);assert(*packet);memcpy(*packet,udp_payload,*size);return 1;}
void wendy_net_guest_datagram_sent(int handle){sent_datagrams++;}
void wendy_net_guest_datagram_closed(int handle){}
void wendy_net_mesh_discard_pending_datagrams(void){discarded++;}
void wendy_net_set_mesh_connector(wendy_net_mesh_begin_fn fn){}
void wendy_net_set_mesh_resolver(wendy_net_mesh_resolve_fn fn){}
void wendy_net_set_service_catalog(wendy_net_service_fn fn){}
int wendy_net_peer_service_catalog(unsigned op,const void *in,size_t n,char *out,size_t cap){return -1;}
esp_err_t wendy_net_peer_agent_endpoint_now(const char *peer,uint8_t address[16],uint16_t *port){return ESP_ERR_NOT_FOUND;}
esp_err_t wendy_net_peer_app_endpoint_now(const char *peer,uint8_t address[16],uint16_t *port){return ESP_ERR_NOT_FOUND;}

int main(int argc,char **argv)
{
 assert(argc==4);size_t kn,cn,rn;uint8_t *key=load(argv[1],&kn),*cert=load(argv[2],&cn),*roots=load(argv[3],&rn);
 import_fixture(&roots,&rn);
 assert(!mbedtls_platform_set_calloc_free(wendy_net_memory_scoped_calloc,wendy_net_memory_scoped_free));
 assert(mbedtls_psa_set_key_slot_table_allocator(wendy_pki_crypto_shared_calloc)==PSA_SUCCESS && !wendy_pki_crypto_init());
 assert(wendy_net_runtime_memory_open());wendy_net_memory_scope_t previous=wendy_net_runtime_scope_enter();
 struct der_source_test source={0};mbedtls_x509_crt_init(&source.chain);assert(!pki_parse_certificate_bundle(&source.chain,cert,cn,false));free(cert);
 prepared=(struct pki_tls_owned_identity){.key=key,.key_size=kn,.trust=roots,.trust_capacity=rn+1,.verify_at=time(NULL),.read_der=read_der_test,.hash_der=hash_der_test,.read_der_range=read_der_range_test,.der_context=&source};
 prepared_roots=(struct wendy_conf_span){roots,rn};wendy_pki_work_enable();
 int listener=socket(AF_INET,SOCK_STREAM,0);assert(listener>=0);struct sockaddr_in address={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
 assert(!bind(listener,(struct sockaddr*)&address,sizeof address));socklen_t len=sizeof address;assert(!getsockname(listener,(struct sockaddr*)&address,&len) && !listen(listener,1));
 printf("%u\n",(unsigned)ntohs(address.sin_port));fflush(stdout);
 int fd=accept(listener,NULL,NULL);assert(fd>=0);close(listener);wendy_net_app_accept(fd);
 bool authenticated=false;unsigned relayed=0;int64_t until=esp_timer_get_time()+30000000;
 while(esp_timer_get_time()<until){
  wendy_net_app_poll();bool worked=wendy_pki_work_poll();
  if(datagram_flows && datagram_flows->flow.connection && datagram_flows->flow.negotiated){assert(wendy_pki_get_peer_role(datagram_flows->flow.connection)==WENDY_PEER_ROLE_OPERATOR);authenticated=true;}
  if(guest_fd>=0){uint8_t bytes[256];ssize_t n=recv(guest_fd,bytes,sizeof bytes,MSG_DONTWAIT);if(n>0){assert(send(guest_fd,bytes,(size_t)n,MSG_DONTWAIT)==n);relayed+=(unsigned)n;}else if(!n){close(guest_fd);guest_fd=-1;}}
  if(!datagram_flows && authenticated)break;
  if(!worked){struct pollfd ready={.fd=fd,.events=POLLIN|POLLOUT};(void)poll(&ready,1,1);}
 }
 assert(authenticated && relayed>0);
 bool stopped=false;for(unsigned i=0;i<1000 && !stopped;i++){stopped=wendy_net_app_stop();(void)wendy_pki_work_poll();}
 assert(stopped && !datagram_flows);if(guest_fd>=0)close(guest_fd);
 mbedtls_x509_crt_free(&source.chain);
 wendy_net_memory_snapshot_t memory;wendy_net_runtime_memory_snapshot(&memory);assert(!memory.current_bytes);
 wendy_net_memory_scope_leave(previous);wendy_net_runtime_memory_close();assert(wendy_net_runtime_memory_drained());
 fprintf(stderr,"COMPOSED primary operator TLS/app actor/WAS1: bytes=%u peak=%zu OFF=0 PASS\n",relayed,memory.high_water_bytes);
 return 0;
}
