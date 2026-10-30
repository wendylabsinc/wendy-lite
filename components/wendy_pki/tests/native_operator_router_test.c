/* Production native TLS and operator mux against an independent Go client. */
#define main ordinary_tls_fixture_main
#include "tls_test.c"
#undef main
#include "native_tls_fixture.h"
#include "wendy_pki_operator.h"
#include "wendy_net_control.h"
#include "wendy_net_carrier.h"
static int fixture_fd;
static ssize_t operator_stream_read(void *ctx,void *out,size_t size)
{(void)ctx;ssize_t n=recv(fixture_fd,out,size,0);return n<0 && (errno==EAGAIN || errno==EWOULDBLOCK) ? -2:n;}
static ssize_t operator_stream_write(void *ctx,const void *out,size_t size)
{(void)ctx;ssize_t n=send(fixture_fd,out,size,0);return n<0 && (errno==EAGAIN || errno==EWOULDBLOCK) ? -3:n;}
static int no_wait(void *ctx,bool writing,int64_t until)
{(void)ctx;(void)writing;(void)until;assert(!"worker waited on I/O");return -1;}
static void transfer(wendy_pki_connection *tls,void *bytes,size_t size,bool writing)
{
 int64_t until=esp_timer_get_time()+15000000;
 for(size_t at=0;at<size;){
  assert(esp_timer_get_time()<until);
  ssize_t n=writing ? wendy_pki_write(tls,(uint8_t *)bytes+at,size-at):wendy_pki_read(tls,(uint8_t *)bytes+at,size-at);
  if(n>0)at+=(size_t)n;else {assert(n==-2 || n==-3);struct pollfd fd={fixture_fd,POLLIN|POLLOUT,0};poll(&fd,1,1);}
 }
}
static ssize_t read_tls(void *ctx,void *bytes,size_t n){return wendy_pki_read(ctx,bytes,n);}
static ssize_t write_tls(void *ctx,const void *bytes,size_t n){return wendy_pki_write(ctx,bytes,n);}
struct echo {struct wnc_carrier *carrier;unsigned count;};
static int echo_frame(void *ctx,const void *data,size_t size,bool control)
{struct echo *e=ctx;assert(size==11 && !memcmp(data,"routed-data",11));e->count++;return wnc_enqueue(e->carrier,data,size,control);}
int main(int argc,char **argv)
{
 assert(argc==5);signal(SIGPIPE,SIG_IGN);
 size_t kn,cn,rn;uint8_t *key=load(argv[1],&kn),*cert=load(argv[2],&cn),*roots=load(argv[3],&rn);
 import_fixture(&roots,&rn);uint8_t *verify_roots=malloc(rn);assert(verify_roots);memcpy(verify_roots,roots,rn);
 assert(!mbedtls_platform_set_calloc_free(wendy_net_memory_scoped_calloc,wendy_net_memory_scoped_free));
 assert(mbedtls_psa_set_key_slot_table_allocator(wendy_pki_crypto_shared_calloc)==PSA_SUCCESS && !wendy_pki_crypto_init());
 struct der_source_test source={0};mbedtls_x509_crt_init(&source.chain);assert(!pki_parse_certificate_bundle(&source.chain,cert,cn,false));free(cert);
 struct pki_tls_owned_identity own={.key=key,.key_size=kn,.trust=roots,.trust_capacity=rn+1,.verify_at=time(NULL),.read_der=read_der_test,.hash_der=hash_der_test,.read_der_range=read_der_range_test,.der_context=&source};
 int listener=socket(AF_INET,SOCK_STREAM,0);assert(listener>=0);struct sockaddr_in address={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
 assert(!bind(listener,(struct sockaddr *)&address,sizeof address));socklen_t len=sizeof address;assert(!getsockname(listener,(struct sockaddr *)&address,&len) && !listen(listener,1));
 printf("%u\n",(unsigned)ntohs(address.sin_port));fflush(stdout);fixture_fd=accept(listener,NULL,NULL);assert(fixture_fd>=0);close(listener);assert(!fcntl(fixture_fd,F_SETFL,O_NONBLOCK));
 struct wendy_pki_stream stream={.read=operator_stream_read,.write=operator_stream_write,.wait=no_wait};wendy_pki_connection *tls=NULL;
 assert(!pki_tls_net_begin(&stream,true,"2558fd76-afc7-466e-9613-6b715296a526","00000000-0000-4000-8000-000000000004",&own,(struct wendy_conf_span){roots,rn},false,&tls));
 if(strcmp(argv[4],"leaf"))assert(!pki_tls_net_allow_operators(tls));
 int result=1;int64_t until=esp_timer_get_time()+15000000;
 while(result!=0 && result!=-1 && esp_timer_get_time()<until){result=pki_tls_net_advance(tls,false,NULL);if(result==-2 || result==-3){struct pollfd fd={fixture_fd,POLLIN|POLLOUT,0};poll(&fd,1,1);}}
 if(!strcmp(argv[4],"device")){
  assert(!result && wendy_pki_get_peer_role(tls)==WENDY_PEER_ROLE_DEVICE);
  assert(!strcmp(tls->mesh_peer,"00000000-0000-4000-8000-000000000005"));
  assert(!wendy_pki_mesh_authenticated_operator(tls));
  uint8_t ack='A';transfer(tls,&ack,1,true);
 }else if(!strcmp(argv[4],"accept")){
  assert(!result && wendy_pki_get_peer_role(tls)==WENDY_PEER_ROLE_OPERATOR && !tls->mesh_peer[0]);
  const uint8_t *der[8];size_t sizes[8],count=0;
  for(const mbedtls_x509_crt *c=mbedtls_ssl_get_peer_cert(&tls->ssl);c && c->raw.len;c=c->next){assert(count<8);der[count]=c->raw.p;sizes[count++]=c->raw.len;}
  tls->authenticated_operator=pki_owned_calloc(1,sizeof *tls->authenticated_operator);assert(tls->authenticated_operator);
  assert(!wendy_pki_operator_chain(der,sizes,count,verify_roots,rn,"2558fd76-afc7-466e-9613-6b715296a526",time(NULL),tls->authenticated_operator));
  pki_tls_net_operator_verified(tls);assert(wendy_pki_mesh_authenticated_operator(tls));
  uint8_t ack='A';transfer(tls,&ack,1,true);
  uint8_t hello[133];transfer(tls,hello,5,false);assert(hello[0]==1);size_t size=wn_get32(hello+1);assert(size<=WN_OPERATOR_HELLO_MAX);transfer(tls,hello+5,size,false);uint8_t instance[16];assert(!wn_operator_hello_read(hello+5,size,instance));
  int n=wn_operator_ready_write(hello+5,sizeof hello-5);assert(n>0);hello[0]=1;wn_put32(hello+1,(uint32_t)n);transfer(tls,hello,(size_t)n+5,true);
  struct wnc_carrier carrier;uint8_t scratch[WN_DATAGRAM_MAX];struct wnc_io io={tls,read_tls,write_tls};assert(!wnc_init(&carrier,&io,scratch,sizeof scratch,8192,65536));assert(!wnc_operator_router(&carrier));struct echo echo={&carrier,0};
  until=esp_timer_get_time()+15000000;
  while(echo.count<2 || carrier.queued){assert(esp_timer_get_time()<until);assert(wnc_pump(&carrier,esp_timer_get_time(),echo_frame,&echo)>=0);}
  wnc_deinit(&carrier);
  resetting=true;assert(!wendy_pki_mesh_authenticated_operator(tls));resetting=false;
  tls->session_deadline_us=esp_timer_get_time()-1;
  assert(!wendy_pki_mesh_authenticated_operator(tls));
 }else assert(result==-1);
 wendy_pki_close(tls);close(fixture_fd);free(verify_roots);mbedtls_x509_crt_free(&source.chain);return 0;
}
