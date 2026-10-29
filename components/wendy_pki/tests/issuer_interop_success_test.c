/* Normal interop driver: the same native async DER constructor used on ESP. */
#include "wendy_pki_internal.h"
#include "wendy_pki_crypto.h"
#include "wendy_pki_parsed_identity.h"
#include "wendy_cert_bundle.h"
#include <mbedtls/platform.h>
#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
int64_t esp_timer_get_time(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return (int64_t)t.tv_sec*1000000+t.tv_nsec/1000;}
bool wendy_pki_reset_in_progress(void){return false;}
ssize_t wendy_test_send(int fd,const void *data,size_t n,int flags){return send(fd,data,n,flags);}
static uint8_t *load(const char *path,size_t *n)
{
    FILE *f=fopen(path,"rb");assert(f);assert(!fseek(f,0,SEEK_END));long size=ftell(f);assert(size>0);
    *n=(size_t)size;rewind(f);uint8_t *p=calloc(1,*n+1);assert(p && fread(p,1,*n,f)==*n);fclose(f);return p;
}
static int read_der(void *context,unsigned index,uint8_t **data,size_t *n)
{
    const mbedtls_x509_crt *p=context;while(p && index--)p=p->next;
    *data=NULL;*n=0;if(!p || !p->raw.len)return 0;
    *data=pki_owned_malloc(p->raw.len);assert(*data);*n=p->raw.len;memcpy(*data,p->raw.p,*n);return 1;
}
static ssize_t io_read(void *context,void *data,size_t n)
{
    ssize_t r=recv(*(int*)context,data,n,0);return r<0 && (errno==EAGAIN || errno==EWOULDBLOCK) ? -2:r;
}
static ssize_t io_write(void *context,const void *data,size_t n)
{
    ssize_t r=send(*(int*)context,data,n,0);return r<0 && (errno==EAGAIN || errno==EWOULDBLOCK) ? -3:r;
}
static int io_wait(void *context,bool write,int64_t deadline)
{
    int64_t remain=deadline-esp_timer_get_time();if(remain<=0)return -1;
    struct pollfd p={.fd=*(int*)context,.events=write ? POLLOUT:POLLIN};return poll(&p,1,(int)(remain/1000+1));
}
static unsigned cached_releases;
static void release_cached_der(void *context){cached_releases++;free(context);}
int main(int argc,char **argv)
{
    assert(argc==14);signal(SIGPIPE,SIG_IGN);
    assert(!mbedtls_platform_set_calloc_free(wendy_net_memory_scoped_calloc,wendy_net_memory_scoped_free));
    assert(!wendy_pki_crypto_init());
    size_t kn,cn,rn;uint8_t *key=load(argv[1],&kn),*cert=load(argv[2],&cn),*roots=load(argv[3],&rn);
    size_t der_size=0;assert(!wendy_cert_bundle_measure(roots,rn,&der_size));
    uint8_t *trust=calloc(1,der_size+1);assert(trust);
    assert(!wendy_cert_bundle_import(roots,rn,trust,der_size,&der_size));free(roots);roots=trust;rn=der_size;
    mbedtls_x509_crt source;mbedtls_x509_crt_init(&source);assert(!pki_parse_certificate_bundle(&source,cert,cn,false));free(cert);
    int fd=socket(AF_INET,SOCK_STREAM,0);assert(fd>=0);
    struct sockaddr_in address={.sin_family=AF_INET,.sin_port=htons((uint16_t)atoi(argv[5])),.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    assert(!connect(fd,(struct sockaddr*)&address,sizeof address));assert(!fcntl(fd,F_SETFL,O_NONBLOCK));
    struct pki_tls_owned_identity own={.key=key,.key_size=kn,.trust=roots,.trust_capacity=rn+1,
        .verify_at=time(NULL),.read_der=read_der,.der_context=&source};
    struct wendy_pki_stream stream={.context=&fd,.read=io_read,.write=io_write,.wait=io_wait};
    bool server=!strcmp(argv[4],"server"),application=atoi(argv[11])!=0;
    wendy_net_memory_t memory=WENDY_NET_MEMORY_INITIALIZER;
    assert(wendy_net_memory_open(&memory,1024*1024,true));
    wendy_net_memory_scope_t previous=wendy_net_memory_scope_enter(&memory,WENDY_NET_MEMORY_EXTERNAL);
    wendy_pki_connection *c=NULL;
    assert(!pki_tls_net_begin(&stream,server,argv[7],argv[8],&own,(struct wendy_conf_span){roots,rn},application,&c));
    if(strcmp(argv[13],"-")){
        size_t size=0;uint8_t *der=load(argv[13],&size);
        struct wendy_pki_net_issuers snapshot={.count=1,.der={der},.sizes={size},
            .context=der,.release=release_cached_der};
        pki_tls_net_add_issuers(c,&snapshot);assert(!snapshot.count && !snapshot.release);
    }
    if(!strcmp(argv[10],"-"))assert(!c->issuers);
    else assert(c->issuers && c->issuers->chain_count==(unsigned)atoi(argv[10]));
    if(atoi(argv[12]))goto done;
    int result=1;unsigned steps=0;
    while(result && ++steps<10000){
        result=pki_tls_net_advance(c,application,argv[9]);
        if(result==-2 || result==-3){assert(io_wait(&fd,result==-3,esp_timer_get_time()+10000000)>0);result=1;}
        else if(result<0){fprintf(stderr,"native handshake failed step=%u state=%d\n",steps,c->ssl.MBEDTLS_PRIVATE(state));abort();}
    }
    assert(!result && steps<10000);
    fprintf(stderr,"native completed role=%s omit=%u wire_count=%u hint=%s\n",argv[4],c->issuers && c->issuers->omit,
        c->issuers ? c->issuers->peer_presented_certificates:0,c->issuers ? c->issuers->hint:"(none)");
    assert((c->issuers && c->issuers->omit)==(atoi(argv[6])==1));
    if(strcmp(argv[13],"-"))assert(c->issuers->peer_presented_certificates==1);
    assert(!strcmp(mbedtls_ssl_get_alpn_protocol(&c->ssl),application ? "wendy-app-mesh-tls/1":"wendy-local-mesh-ble/2"));
    printf("native role=%s omit=%u received_count=%u hint=%s\n",argv[4],c->issuers && c->issuers->omit,c->issuers ? c->issuers->peer_presented_certificates:0,c->issuers ? c->issuers->hint:"(none)");
    const char message[]="hello";size_t sent=0,received=0;char reply[sizeof message];
    while(sent<sizeof message){int n=wendy_pki_write(c,message+sent,sizeof message-sent);if(n>0)sent+=(size_t)n;else{assert(n==-2 || n==-3);assert(io_wait(&fd,n==-3,esp_timer_get_time()+10000000)>0);}}
    while(received<sizeof reply){int n=wendy_pki_read(c,reply+received,sizeof reply-received);if(n>0)received+=(size_t)n;else{assert(n==-2 || n==-3);assert(io_wait(&fd,n==-3,esp_timer_get_time()+10000000)>0);}}
    assert(!memcmp(reply,message,sizeof reply));
done:
    wendy_pki_close(c);close(fd);
    assert(cached_releases==(unsigned)(strcmp(argv[13],"-")!=0));
    wendy_net_memory_scope_leave(previous);
    wendy_net_memory_snapshot_t snapshot;wendy_net_memory_snapshot(&memory,&snapshot);
    fprintf(stderr,"issuer scoped peak=%zu retained=%zu allocations=%zu reservations=%zu\n",
        snapshot.high_water_bytes,snapshot.current_bytes,snapshot.allocation_count,snapshot.reservation_count);
    assert(snapshot.high_water_bytes && !snapshot.current_bytes && !snapshot.allocation_count && !snapshot.reservation_count);
    wendy_net_memory_close(&memory);assert(wendy_net_memory_drained(&memory));
    mbedtls_x509_crt_free(&source);return 0;
}
