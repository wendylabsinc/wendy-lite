#include "artifact_crypto.h"
#include "esp_timer.h"
#include "esp_log.h"
#include "http_parser.h"
#include "wendy_pki_internal.h"
#include "wendy_pki_work.h"
#include "wendy_pki_parsed_identity.h"
#include "wendy_cert_bundle.h"
#include "wendy_pki_dns.h"
#include "wendy_pki_stream_io.h"
#include <arpa/inet.h>
#include <psa/crypto.h>
#include "wendy_pki_verify.h"
#include "wendy_pki_crypto.h"
#include "wendy_pki_certificate_policy.h"
#include "wendy_peer_identity.h"
#include "wendy_operator_auth.h"
#include "wendy_net_binary.h"
#if CONFIG_WENDY_MESH_LEAF
#define LEGACY_MESH_ALPN WENDY_PKI_MESH_ALPN
#else
#define LEGACY_MESH_ALPN "" /* Legacy constructors reject this disabled profile. */
#endif
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdatomic.h>
#include <mbedtls/platform.h>
#include <mbedtls/md.h>
#if CONFIG_WENDY_MESH_LEAF
#include <mbedtls/base64.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#if ESP_PLATFORM
#include "sdkconfig.h"
#include "esp_heap_caps.h"
#include "esp_memory_utils.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include <net/if.h>
#endif


/* Provided by the bounded-reassembly patch in our pinned Mbed TLS tree. */
#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
void mbedtls_ssl_release_handshake_buffer(mbedtls_ssl_context *ssl);
void mbedtls_ssl_compact_input_buffer(mbedtls_ssl_context *ssl);
int mbedtls_ssl_setup_small_input(mbedtls_ssl_context *ssl,const mbedtls_ssl_config *conf);
#endif


struct pki_presented_chain
{
    unsigned count;
    int (*read)(void *,unsigned,uint8_t **,size_t *);
    int (*read_range)(void *,unsigned,size_t,uint8_t *,size_t,const uint8_t[32]);
    void *context;
    struct {size_t size;uint8_t hash[32];} part[8];
};

/* A context keeps its initiating resource owner across worker/com-task moves.
 * Entering a closed owner still rejects growth; freeing remains permitted. */
static wendy_net_memory_scope_t connection_scope(wendy_pki_connection *c)
{
    return wendy_net_memory_scope_enter(c->allocation_scope.owner,c->allocation_scope.placement);
}
static int connection_read(wendy_pki_connection *c,unsigned char *bytes,size_t size)
{
    wendy_net_memory_scope_t previous=connection_scope(c);
    int result=mbedtls_ssl_read(&c->ssl,bytes,size);
    wendy_net_memory_scope_leave(previous);return result;
}
static int connection_write(wendy_pki_connection *c,const unsigned char *bytes,size_t size)
{
    wendy_net_memory_scope_t previous=connection_scope(c);
    int result=mbedtls_ssl_write(&c->ssl,bytes,size);
    wendy_net_memory_scope_leave(previous);return result;
}
static void release_presented_chain(wendy_pki_connection *c)
{
    c->config.MBEDTLS_PRIVATE(f_wendy_certificate_der)=NULL;
    c->config.MBEDTLS_PRIVATE(p_wendy_certificate_der)=NULL;
    pki_owned_free(c->presented_chain);c->presented_chain=NULL;
}
/* Callback lives only within the synchronous TLS constructor. Hash-check the
 * entire public part before copying any requested range into a TLS fragment.
 * The independently verified own leaf remains parsed for CertificateVerify. */
static int read_presented_der(void *context,unsigned index,size_t offset,
                              unsigned char *output,size_t count)
{
    wendy_pki_connection *c=context;
    struct pki_presented_chain *source=c->presented_chain;
    if (!source || index>=source->count || (c->issuers && c->issuers->omit && index)) return output ? -1:0;
    size_t expected=source->part[index].size;
    if (!output) return count ? -1:(int)expected;
    if (offset>expected || count>expected-offset) return -1;
    if (!index && c->certificate.raw.len) {
        if (c->certificate.raw.len!=expected) return -1;
        memcpy(output,c->certificate.raw.p+offset,count);return (int)count;
    }
    if(source->read_range)
        return source->read_range(source->context,index,offset,output,count,source->part[index].hash);
    uint8_t *der=NULL,hash[32];size_t size=0;
    int loaded=source->read(source->context,index,&der,&size);
    bool valid=loaded==1 && der && size==expected &&
        !wendy_pki_sha256(der,size,hash) &&
        !memcmp(hash,source->part[index].hash,32);
    if (valid) memcpy(output,der+offset,count);
    pki_owned_free(der);return valid ? (int)count:-1;
}
static int pin_presented_chain(wendy_pki_connection *c,
    int (*read)(void *,unsigned,uint8_t **,size_t *),
    int (*read_range)(void *,unsigned,size_t,uint8_t *,size_t,const uint8_t[32]),void *context,unsigned cached_count)
{
    if (!c->certificate.next && !cached_count) return 0;
    struct pki_presented_chain *source=c->presented_chain;
    if (!source) return -1;
    source->read=read;source->read_range=read_range;source->context=context;
    size_t released=0;
    if(cached_count){
        uint8_t hash[32];
        if(cached_count>source->count || !cached_count ||
           c->certificate.raw.len!=source->part[0].size ||
           wendy_pki_sha256(c->certificate.raw.p,c->certificate.raw.len,hash) ||
           memcmp(hash,source->part[0].hash,32))return -1;
        source->count=cached_count;
    }else source->count=0;
    for (const mbedtls_x509_crt *part=cached_count ? NULL:&c->certificate;part;part=part->next) {
        unsigned index=source->count;
        if (index==8 || !part->raw.len || part->raw.len>65536 ||
            wendy_pki_sha256(part->raw.p,part->raw.len,source->part[index].hash)) {
            return -1;
        }
        source->part[index].size=part->raw.len;source->count++;
        if (index)released+=part->raw.len;
    }
    c->presented_chain=source;
    c->config.MBEDTLS_PRIVATE(f_wendy_certificate_der)=read_presented_der;
    c->config.MBEDTLS_PRIVATE(p_wendy_certificate_der)=c;
    mbedtls_x509_crt *issuers=c->certificate.next;c->certificate.next=NULL;
    if(issuers){mbedtls_x509_crt_free(issuers);mbedtls_free(issuers);}
#if ESP_PLATFORM && CONFIG_WENDY_NET_PEER
    ESP_LOGI("wendy_pki","verified own issuers streamed: parts=%u DERbytes=%u free=%u largest=%u",
        source->count,(unsigned)released,
        (unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT),
        (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
#endif
    (void)released;
    return 0;
}

/* Only exact independently pinned issuers participate in this optional hint.
 * Ordinary trust verification and the real service ALPN remain mandatory. */
static int issuer_identity(const mbedtls_x509_crt *leaf,uint8_t output[32])
{
    uint8_t parts[64];
    if(!leaf || !leaf->raw.len ||
       wendy_pki_sha256(leaf->issuer_raw.p,leaf->issuer_raw.len,parts) ||
       wendy_pki_sha256(leaf->authority_key_id.keyIdentifier.p,
                        leaf->authority_key_id.keyIdentifier.len,parts+32))return -1;
    return wendy_pki_sha256(parts,sizeof parts,output);
}

static struct pki_issuer_state *prepare_issuer_hint(wendy_pki_connection *c)
{
    struct pki_presented_chain *source=c->presented_chain;
    uint8_t hashes[7][32],identity[32];
    if(!source || source->count<2 || source->count>8 ||
       issuer_identity(&c->certificate,identity))return NULL;
    for(unsigned i=1;i<source->count;i++){
        bool pinned=false;
        for(const mbedtls_x509_crt *root=&c->roots;root && root->raw.len;root=root->next){
            uint8_t hash[32];
            if(root->raw.len==source->part[i].size &&
               !wendy_pki_sha256(root->raw.p,root->raw.len,hash) &&
               !memcmp(hash,source->part[i].hash,32)){pinned=true;break;}
        }
        if(!pinned)return NULL;
        memcpy(hashes[i-1],source->part[i].hash,32);
    }
    /* Optional optimization: admission failure preserves ordinary full-chain
     * TLS, with no allocation or persistent global cache while mesh is off. */
    struct pki_issuer_state *state=pki_owned_calloc(1,sizeof *state);
    if(!state)return NULL;
    if(pki_issuer_hint(hashes,source->count-1,state->hint)){pki_owned_free(state);return NULL;}
    memcpy(state->own_issuer_identity,identity,32);return state;
}

static int select_server_issuers(mbedtls_ssl_context *ssl)
{
    wendy_pki_connection *c=ssl->MBEDTLS_PRIVATE(p_bio);
    if(c && c->issuers)
        c->issuers->omit=pki_client_hello_offers(ssl->MBEDTLS_PRIVATE(in_msg),
            ssl->MBEDTLS_PRIVATE(in_hslen),c->issuers->hint);
    return 0;
}

static int configure_mesh_alpn(wendy_pki_connection *c,const char *const *protocols)
{
    wendy_net_memory_scope_t previous=connection_scope(c);
    c->issuers=prepare_issuer_hint(c);
    wendy_net_memory_scope_leave(previous);
    if(c->issuers){
        c->issuers->protocols[0]=protocols[0];
        if(c->config.MBEDTLS_PRIVATE(endpoint)==MBEDTLS_SSL_IS_CLIENT){
            c->issuers->protocols[1]=c->issuers->hint;
            protocols=c->issuers->protocols;
        }else mbedtls_ssl_conf_cert_cb(&c->config,select_server_issuers);
    }
    /* Auxiliary offer only: servers select the unchanged real service ALPN. */
    return mbedtls_ssl_conf_alpn_protocols(&c->config,protocols);
}


static int io_recv(void *context, unsigned char *buf, size_t size)
{
    wendy_pki_connection *c = context;
    if (c->stream.read) {
        ssize_t n = c->stream.read(c->stream.context, buf, size);
        return pki_stream_read_result(n,size);
    }
    int n = recv(c->fd, buf, size, 0);
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
        return MBEDTLS_ERR_SSL_WANT_READ;
    return n<0 ? ((errno==ECONNRESET || errno==EPIPE) ? MBEDTLS_ERR_NET_CONN_RESET:MBEDTLS_ERR_NET_RECV_FAILED):n;
}
static int io_send(void *context, const unsigned char *buf, size_t size)
{
    wendy_pki_connection *c = context;
    if (c->stream.write) {
        ssize_t n = c->stream.write(c->stream.context, buf, size);
        return pki_stream_write_result(n,size);
    }
    int n = send(c->fd, buf, size, 0);
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ||
                 errno == ENOBUFS || errno == ENOMEM)) {
#if ESP_PLATFORM
        /* select() may report a writable TCP window while lwIP cannot allocate
         * its packet. Let lower-priority carrier/relay tasks drain their queues
         * before retrying; otherwise the handshake worker can starve them. */
        if (errno == ENOBUFS || errno == ENOMEM) vTaskDelay(1);
#endif
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }
    return n<0 ? ((errno==ECONNRESET || errno==EPIPE) ? MBEDTLS_ERR_NET_CONN_RESET:MBEDTLS_ERR_NET_SEND_FAILED):n;
}
static void release_mesh_roots(wendy_pki_connection *c)
{
    if(c->mesh_roots_prefixed)pki_owned_free(c->mesh_roots);
    else free(c->mesh_roots); /* Raw enrollment trust transfers retain their ABI. */
    c->mesh_roots=NULL;c->mesh_roots_size=0;c->mesh_roots_prefixed=false;
    wendy_net_memory_release(&c->raw_roots_reservation);
}
static bool reserve_raw_roots(wendy_pki_connection *c,const uint8_t *bytes,size_t size)
{
    if(!c->allocation_scope.owner)return true;
    wendy_net_memory_placement_t placement=WENDY_NET_MEMORY_INTERNAL;
#if ESP_PLATFORM
    if(esp_ptr_external_ram(bytes))placement=WENDY_NET_MEMORY_EXTERNAL;
    size_t allocated=heap_caps_get_allocated_size((void *)bytes);
    if(allocated>size)size=allocated;
#else
    (void)bytes;
#endif
    return wendy_net_memory_reserve(c->allocation_scope.owner,
        &c->raw_roots_reservation,size,placement);
}
void wendy_pki_close(wendy_pki_connection *c)
{
    if (!c) return;
    wendy_net_memory_scope_t previous=connection_scope(c);
    release_presented_chain(c);
    pki_tls_input_return(c->setup_input_reservation,c->setup_input_capacity);
    wendy_pki_handshake_release(c);
    mbedtls_ssl_free(&c->ssl);
    mbedtls_ssl_config_free(&c->config);
    mbedtls_x509_crt_free(&c->roots);
    mbedtls_x509_crt_free(&c->certificate);
    mbedtls_pk_free(&c->key);
    release_mesh_roots(c);
    pki_public_chain_free(c->public_chain);
    pki_owned_free(c->authenticated_peer);
    pki_owned_free(c->issuers);
    if (c->fd >= 0) close(c->fd);
    pki_owned_free(c);
    wendy_pki_crypto_cleanup();
    wendy_net_memory_scope_leave(previous);
}

/* Add Wendy's algorithm restrictions without overriding certificate-chain,
 * hostname, validity, or key-usage failures reported by mbedTLS. */
static int certificate_policy(void *context, mbedtls_x509_crt *cert, int depth,
                              uint32_t *flags)
{
    (void)depth;
    wendy_pki_connection *c = context;
    bool anchor = false;
    for (const mbedtls_x509_crt *root = &c->roots; root; root = root->next) {
        if (root->raw.len == cert->raw.len &&
            !memcmp(root->raw.p, cert->raw.p, root->raw.len)) {
            anchor = true;
            break;
        }
    }
    if (wendy_pki_certificate_policy(cert, anchor))
        *flags |= MBEDTLS_X509_BADCERT_OTHER;
    if (c->mesh_tenant[0]) {
        time_t expiry;
        if (pki_parsed_peer_expiry(cert,&expiry))
            *flags |= MBEDTLS_X509_BADCERT_OTHER;
        else if (!c->operator_expires || expiry < c->operator_expires)
            c->operator_expires = expiry;
    }
    return 0;
}

static int configure_failed(const char *stage, int error)
{
    ESP_LOGE("wendy_pki", "TLS setup failed at %s (error=%d)", stage, error);
#if ESP_PLATFORM
    ESP_LOGE("wendy_pki", "TLS heap: free=%u largest=%u dma_free=%u dma_largest=%u",
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT),
             (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT),
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_DMA | MALLOC_CAP_INTERNAL),
             (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_DMA | MALLOC_CAP_INTERNAL));
#endif
    (void)stage;
    (void)error;
    return -1;
}

/* After complete TLS1.3 authentication these roles retain the checked UUID,
 * role, identity/SPKI hashes and full-path monotonic expiry. Record protection
 * uses the negotiated traffic keys; renegotiation/post-handshake certificate
 * authentication is not supported. No certificate object is needed again.
 * Keep the private key for native route signatures. Full routers retain their
 * independent origin-proof material until its separate cache is integrated. */
static void release_session_certificates(wendy_pki_connection *c)
{
#if defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
    mbedtls_x509_crt *leaf=c->ssl.MBEDTLS_PRIVATE(session)->MBEDTLS_PRIVATE(peer_cert);
    if (leaf) {
        c->ssl.MBEDTLS_PRIVATE(session)->MBEDTLS_PRIVATE(peer_cert)=NULL;
        mbedtls_x509_crt_free(leaf);
        mbedtls_free(leaf);
    }
#endif
    mbedtls_x509_crt_free(&c->certificate);
}
static void release_verified_paths(wendy_pki_connection *c)
{
    c->compact_records=true;
    release_session_certificates(c);
    mbedtls_ssl_conf_ca_chain(&c->config,NULL,NULL);
    mbedtls_x509_crt_free(&c->roots);
    release_mesh_roots(c);
    c->mesh_roots=NULL;
    c->mesh_roots_size=0;
#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
    mbedtls_ssl_release_handshake_buffer(&c->ssl);
    mbedtls_ssl_compact_input_buffer(&c->ssl);
#endif
}
/* A TLS1.3 server has serialized its Certificate message before entering
 * CERTIFICATE_VERIFY, even if its output is still backpressured. Compact
 * roles need no local issuer objects afterward.
 * Release them before receiving a different operator/device issuing path,
 * while retaining the private key, own leaf, roots and verified path expiry. */
static int handshake_step_direct(wendy_pki_connection *c,bool compact_server)
{
    struct pki_presented_chain *source=c->presented_chain;
    if(compact_server && !c->public_chain && source && source->read &&
       c->config.MBEDTLS_PRIVATE(endpoint)==MBEDTLS_SSL_IS_CLIENT &&
       c->ssl.MBEDTLS_PRIVATE(state)==MBEDTLS_SSL_SERVER_CERTIFICATE &&
       c->certificate.raw.len && c->certificate.raw.len==source->part[0].size){
        /* Own path and key pair passed configure(). TLS1.3 CertificateRequest
         * has now been collected. The pinned DER callback can stream the leaf
         * as well as issuers; CertificateVerify uses the retained private key.
         * Return the parsed leaf for both peer PQC verification and our own
         * backpressured Certificate flight. Every source range is hash-bound. */
        size_t released=c->certificate.raw.len;
        mbedtls_x509_crt_free(&c->certificate);mbedtls_x509_crt_init(&c->certificate);
#if ESP_PLATFORM && CONFIG_WENDY_NET_PEER
        ESP_LOGI("wendy_pki","client verified own leaf streamed: DERbytes=%u ranges=%u free=%u largest=%u",
            (unsigned)released,source->read_range ? 1u:0u,
            (unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT),
            (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
#endif
        (void)released;
    }
    /* CertificateVerify has finished before SERVER_FINISHED, including any
     * backpressured signature output. These TLS1.3-only endpoint roles never
     * sign routing proofs or renegotiate. Keep the independently checked own
     * path deadline, but return their leaf and signing key before allocating
     * the client's different (potentially PQC) certificate path. Full routers
     * retain their private key for route signatures. */
    if (compact_server && !c->public_chain &&
        c->config.MBEDTLS_PRIVATE(endpoint)==MBEDTLS_SSL_IS_SERVER &&
        (c->ssl.MBEDTLS_PRIVATE(state)==MBEDTLS_SSL_SERVER_FINISHED ||
         c->ssl.MBEDTLS_PRIVATE(state)==MBEDTLS_SSL_CLIENT_CERTIFICATE) &&
        c->certificate.raw.len && c->device_expires>time(NULL)) {
        mbedtls_x509_crt_free(&c->certificate);
        mbedtls_pk_free(&c->key);
#if ESP_PLATFORM && CONFIG_WENDY_NET_PEER
        ESP_LOGI("wendy_pki","server signature complete; own leaf/key released: free=%u largest=%u",
            (unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT),
            (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
#endif
    }
    if ((compact_server || c->public_chain) && c->config.MBEDTLS_PRIVATE(endpoint)==MBEDTLS_SSL_IS_SERVER &&
        (c->ssl.MBEDTLS_PRIVATE(state)==MBEDTLS_SSL_CERTIFICATE_VERIFY ||
         c->ssl.MBEDTLS_PRIVATE(state)==MBEDTLS_SSL_SERVER_FINISHED ||
         c->ssl.MBEDTLS_PRIVATE(state)==MBEDTLS_SSL_CLIENT_CERTIFICATE) &&
        c->certificate.next && c->device_expires>time(NULL)) {
        mbedtls_x509_crt *issuers=c->certificate.next;c->certificate.next=NULL;
        mbedtls_x509_crt_free(issuers);mbedtls_free(issuers);
#if ESP_PLATFORM && CONFIG_WENDY_NET_PEER
        ESP_LOGI("wendy_pki","server certificate serialized; own issuers released: free=%u largest=%u",
            (unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT),
            (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
#endif
    }
    int state=c->ssl.MBEDTLS_PRIVATE(state);
    struct pki_issuer_state *issuers=c->issuers;
    if(issuers && c->config.MBEDTLS_PRIVATE(endpoint)==MBEDTLS_SSL_IS_CLIENT &&
       state==MBEDTLS_SSL_CLIENT_CERTIFICATE){
        const char *selected=mbedtls_ssl_get_alpn_protocol(&c->ssl);
        uint8_t peer_issuer[32];
        /* The public getter exposes only the established session, which is
         * installed after we write our certificate. Read this verified pending
         * session while its exclusively loaned handshake context is still live. */
        const mbedtls_ssl_session *pending=c->ssl.MBEDTLS_PRIVATE(session_negotiate);
        const mbedtls_x509_crt *peer=pending ? pending->MBEDTLS_PRIVATE(peer_cert):NULL;
        /* Server chain, CertificateVerify and Finished have passed. The wire
         * count survives library compaction of the verified parsed chain. */
        issuers->omit=issuers->peer_presented_certificates==1 && selected &&
            !strcmp(selected,issuers->protocols[0]) &&
            !mbedtls_ssl_get_verify_result(&c->ssl) &&
            !issuer_identity(peer,peer_issuer) &&
            !memcmp(peer_issuer,issuers->own_issuer_identity,32);
    }
    int result=mbedtls_ssl_handshake_step(&c->ssl);
    if(!result && issuers && state==MBEDTLS_SSL_SERVER_CERTIFICATE &&
       c->config.MBEDTLS_PRIVATE(endpoint)==MBEDTLS_SSL_IS_CLIENT &&
       c->ssl.MBEDTLS_PRIVATE(state)==MBEDTLS_SSL_CERTIFICATE_VERIFY)
        issuers->peer_presented_certificates=pki_certificate_message_count(
            c->ssl.MBEDTLS_PRIVATE(in_msg),c->ssl.MBEDTLS_PRIVATE(in_hslen));
    return result;
}

struct handshake_cpu {wendy_pki_connection *c;bool compact;int result;};
static void handshake_cpu(void *context)
{
    struct handshake_cpu *job=context;
    wendy_net_memory_scope_t previous=connection_scope(job->c);
    job->result=handshake_step_direct(job->c,job->compact);
    wendy_net_memory_scope_leave(previous);
}
static int handshake_step(wendy_pki_connection *c,bool compact)
{
    struct handshake_cpu job={.c=c,.compact=compact,.result=MBEDTLS_ERR_SSL_INTERNAL_ERROR};
    return wendy_pki_work_run(handshake_cpu,&job) ? MBEDTLS_ERR_SSL_INTERNAL_ERROR:job.result;
}

static void release_identity_input(struct pki_tls_owned_identity *owned)
{
    if (!owned) return;
    volatile uint8_t *key = owned->key;
    for (size_t i = 0; key && i < owned->key_size; i++) key[i] = 0;
    free(owned->key);
    free(owned->certificate);
    free(owned->trust);
    pki_tls_input_return(owned->input_reservation,owned->input_reserve);
    pki_public_chain_free(owned->public_chain);
    memset(owned, 0, sizeof *owned);
}
/* Only a self-signed CA is an implicit common root. A locally pinned
 * intermediate may be absent from the remote peer's trust store; keep it in
 * the presentation unless the exact-issuer optimization separately agrees. */
static bool presented_self_signed_root(mbedtls_x509_crt *cert)
{
    if(!cert || !cert->MBEDTLS_PRIVATE(ca_istrue) ||
       cert->issuer_raw.len!=cert->subject_raw.len ||
       memcmp(cert->issuer_raw.p,cert->subject_raw.p,cert->issuer_raw.len))return false;
    const uint8_t *input=cert->tbs.p;size_t size=cert->tbs.len;
    uint8_t digest[MBEDTLS_MD_MAX_SIZE];
    bool pure=cert->MBEDTLS_PRIVATE(sig_pk)==MBEDTLS_PK_SIGALG_MLDSA65;
#if defined(MBEDTLS_X509_MLDSA87)
    pure=pure || cert->MBEDTLS_PRIVATE(sig_pk)==MBEDTLS_PK_SIGALG_MLDSA87;
#endif
    if(!pure){
        const mbedtls_md_info_t *md=mbedtls_md_info_from_type(cert->MBEDTLS_PRIVATE(sig_md));
        if(!md || mbedtls_md(md,input,size,digest))return false;
        input=digest;size=mbedtls_md_get_size(md);
    }
    return !mbedtls_pk_verify_ext(cert->MBEDTLS_PRIVATE(sig_pk),&cert->pk,
        cert->MBEDTLS_PRIVATE(sig_md),input,size,cert->MBEDTLS_PRIVATE(sig).p,cert->MBEDTLS_PRIVATE(sig).len);
}
/* Omit only a provable self-signed root exactly present in local trust. */
static void trim_presented_anchor(wendy_pki_connection *c)
{
    mbedtls_x509_crt *previous = &c->certificate;
    while (previous->next && previous->next->next) previous = previous->next;
    mbedtls_x509_crt *tail = previous->next;
    if (!presented_self_signed_root(tail)) return;
    for (mbedtls_x509_crt *root = &c->roots; root; root = root->next) {
        if (root->raw.len && root->raw.len == tail->raw.len &&
            !memcmp(root->raw.p, tail->raw.p, tail->raw.len)) {
            previous->next = NULL;
            ESP_LOGI("wendy_pki", "omitted pinned TLS trust anchor (%u DER bytes)", (unsigned)tail->raw.len);
            mbedtls_x509_crt_free(tail);
            mbedtls_free(tail);
            return;
        }
    }
}
/* Contiguous imported DER fallback when indexed flash sources are unavailable. */
static int parse_owned_certificates(mbedtls_x509_crt *chain,struct pki_tls_owned_identity *owned)
{
    return pki_parse_certificate_bundle(chain,(const uint8_t*)owned->certificate,
                                       owned->certificate_size,false);
}
static int parse_owned_der(mbedtls_x509_crt *chain,struct pki_tls_owned_identity *owned,bool leaf_only)
{
    for(unsigned i=0;i<=8;i++) {
        uint8_t *der=NULL;size_t size=0;
        int status=owned->read_der(owned->der_context,i,&der,&size);
        if(!status && !der && !size)return i ? 0:MBEDTLS_ERR_X509_INVALID_FORMAT;
        if(status==MBEDTLS_ERR_X509_ALLOC_FAILED){pki_owned_free(der);return status;}
        if(status!=1 || !der || !size || size>65536 || i==8) {
            pki_owned_free(der);return MBEDTLS_ERR_X509_INVALID_FORMAT;
        }
        int r=mbedtls_x509_crt_parse_der_nocopy(chain,der,size);
        if(r){pki_owned_free(der);return r;}
        mbedtls_x509_crt *part=chain;
        while(part && part->raw.p!=der)part=part->next;
        if(!part){pki_owned_free(der);return MBEDTLS_ERR_X509_INVALID_FORMAT;}
        part->MBEDTLS_PRIVATE(own_buffer)=1;
        if(leaf_only)return 0;
    }
    return MBEDTLS_ERR_X509_INVALID_FORMAT;
}

/* All roots are DER before TLS setup. The connection owns this immutable
 * bundle until its parsed anchors are released, including multi-root trust. */
static int parse_owned_roots(wendy_pki_connection *c,struct wendy_conf_span *roots)
{
    return pki_parse_certificate_bundle(&c->roots,c->mesh_roots,roots->size,true);
}

/* Memoize only a successfully verified LOCAL identity path. Re-read/hash
 * every exact source DER part and the current trust bundle before reuse;
 * renewal or changed roots/principal force a full parse and verification.
 * The private key is still parsed/matched and remote authentication runs on
 * every connection. No NVS descriptor is treated as verification evidence. */
static pthread_mutex_t own_path_lock=PTHREAD_MUTEX_INITIALIZER;
static struct {
    bool valid;
    uint8_t hash[32];
    time_t verified_at,expires;
    unsigned presented_count;
} own_path_cache;

static int own_path_hash(struct pki_tls_owned_identity *owned,
    struct wendy_conf_span roots,const char *principal,
    struct pki_presented_chain *source,uint8_t hash[32])
{
    uint8_t trust_hash[32];
    if(!principal || strlen(principal)>512 || !source ||
       wendy_pki_sha256(roots.data,roots.size,trust_hash))return -1;
    source->count=0;
    for(unsigned i=0;i<=8;i++){
        uint8_t *der=NULL;size_t size=0;
        uint8_t digest[32];
        int status=owned->hash_der ? owned->hash_der(owned->der_context,i,digest,&size):
            owned->read_der(owned->der_context,i,&der,&size);
        if(!status && !der && !size)break;
        if(status!=1 || (!owned->hash_der && !der) || !size || size>65536 || i==8){pki_owned_free(der);return -1;}
        int r=owned->hash_der ? 0:wendy_pki_sha256(der,size,digest);
        pki_owned_free(der);if(r)return -1;
        memcpy(source->part[i].hash,digest,32);
        source->part[i].size=size;source->count++;
    }
    if(!source->count)return -1;
    psa_hash_operation_t operation=PSA_HASH_OPERATION_INIT;
    const uint8_t domain[]="wendy/local-identity-source/1";
    size_t written=0;int result=-1;
    if(psa_hash_setup(&operation,PSA_ALG_SHA_256)!=PSA_SUCCESS ||
       psa_hash_update(&operation,domain,sizeof domain)!=PSA_SUCCESS ||
       psa_hash_update(&operation,trust_hash,sizeof trust_hash)!=PSA_SUCCESS)goto done;
    size_t principal_size=strlen(principal);
    uint8_t header[4];
    for(unsigned i=0;i<4;i++)header[3-i]=(uint8_t)(principal_size>>(8*i));
    if(psa_hash_update(&operation,header,sizeof header)!=PSA_SUCCESS ||
       psa_hash_update(&operation,(const uint8_t *)principal,principal_size)!=PSA_SUCCESS)goto done;
    for(unsigned part=0;part<source->count;part++){
        for(unsigned i=0;i<4;i++)header[3-i]=(uint8_t)(source->part[part].size>>(8*i));
        if(psa_hash_update(&operation,header,sizeof header)!=PSA_SUCCESS ||
           psa_hash_update(&operation,source->part[part].hash,32)!=PSA_SUCCESS)goto done;
    }
    if(psa_hash_finish(&operation,hash,32,&written)==PSA_SUCCESS && written==32)result=0;
done:
    psa_hash_abort(&operation);return result;
}
static bool own_path_reuse(const uint8_t hash[32],time_t now,time_t *expires,unsigned *count)
{
    pthread_mutex_lock(&own_path_lock);
    bool hit=own_path_cache.valid && now>=own_path_cache.verified_at &&
        now<own_path_cache.expires && !memcmp(hash,own_path_cache.hash,32);
    if(hit){*expires=own_path_cache.expires;*count=own_path_cache.presented_count;}
    pthread_mutex_unlock(&own_path_lock);return hit;
}
static void own_path_remember(const uint8_t hash[32],time_t now,time_t expires,unsigned count)
{
    pthread_mutex_lock(&own_path_lock);
    memcpy(own_path_cache.hash,hash,32);own_path_cache.verified_at=now;
    own_path_cache.expires=expires;own_path_cache.presented_count=count;
    own_path_cache.valid=expires>now && count && count<=8;
    pthread_mutex_unlock(&own_path_lock);
}

static int setup_reserved_records(wendy_pki_connection *c,size_t preferred)
{
    if(!c->setup_input_reservation && preferred==PKI_TLS_INPUT_RESERVE){
        c->setup_input_reservation=pki_tls_input_take(preferred);
        c->setup_input_capacity=preferred;
    }

    bool transferred=c->setup_input_reservation!=NULL;
    int r=transferred ? mbedtls_ssl_setup_with_preallocated_input(&c->ssl,&c->config,
        &c->setup_input_reservation,preferred) :
        mbedtls_ssl_setup_with_input_reserve(&c->ssl,&c->config,preferred);
    if(!r && transferred)
        ESP_LOGI("wendy_pki","TLS early input transferred: bytes=%u",(unsigned)preferred);
    if(preferred && (r==PSA_ERROR_INSUFFICIENT_MEMORY || r==MBEDTLS_ERR_SSL_ALLOC_FAILED)){
        /* A preferred contiguous hole is an allocation strategy, not a TLS
         * limit. Start with the ordinary record buffer when it does not fit;
         * bounded handshake reassembly still grows to the actual message.
         * Retry only before any BIO, handshake or peer input is attached. */
        mbedtls_ssl_free(&c->ssl);mbedtls_ssl_init(&c->ssl);
        pki_tls_input_return(c->setup_input_reservation,c->setup_input_capacity);c->setup_input_reservation=NULL;
        pki_tls_input_discard_cached();
        r=mbedtls_ssl_setup(&c->ssl,&c->config);
        ESP_LOGI("wendy_pki","TLS preferred input unavailable: preferred=%u ordinary_setup=%d",
                 (unsigned)preferred,r);
    }
    return r;
}

static int configure_direct(wendy_pki_connection *c, int server, const uint8_t *key,
    size_t key_size, struct wendy_conf_span cert, struct wendy_conf_span roots,
    struct pki_tls_owned_identity *owned, const char *principal, time_t verify_at,
    bool consume_trust,bool stream_identity)
{
    int (*read_der)(void *,unsigned,uint8_t **,size_t *)=owned ? owned->read_der:NULL;
    int (*read_range)(void *,unsigned,size_t,uint8_t *,size_t,const uint8_t[32])=
        owned ? owned->read_der_range:NULL;
    void *der_context=owned ? owned->der_context:NULL;
    size_t input_reserve=owned && owned->input_reserve ? owned->input_reserve : 24576;
    mbedtls_ssl_init(&c->ssl); mbedtls_ssl_config_init(&c->config);
    mbedtls_x509_crt_init(&c->roots); mbedtls_x509_crt_init(&c->certificate);
    mbedtls_pk_init(&c->key);
    if(owned && owned->input_reservation){
        if(!read_der || !owned->reserve_records_first || !owned->input_reserve)
            return configure_failed("early input reservation",MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
        c->setup_input_reservation=owned->input_reservation;
        c->setup_input_capacity=owned->input_reserve;
        owned->input_reservation=NULL;
    }
    int r = wendy_pki_crypto_init();
    if (r) return configure_failed("crypto initialization", r);
    if (!roots.data || !roots.size || roots.size > 16384 ||
        (verify_at && ((const uint8_t*)roots.data)[0]!=0x30))
        return configure_failed("CA bundle input", MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
    r = mbedtls_ssl_config_defaults(&c->config,
        server ? MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT,
        MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (r) return configure_failed("mbedtls_ssl_config_defaults", r);
    c->config.MBEDTLS_PRIVATE(wendy_input_recycle)=pki_tls_input_recycle;
    mbedtls_ssl_conf_authmode(&c->config, MBEDTLS_SSL_VERIFY_REQUIRED);
    c->config.MBEDTLS_PRIVATE(wendy_compact_peer_chain)=consume_trust;
#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
    /* Do not allocate a17KiB intermediate input beside the26KiB preferred
     * buffer on SRAM-only peers. Explicit application-idle compaction still
     * reaches2KiB, with the unchanged record/reassembly growth limits. */
#if ESP_PLATFORM
    c->config.MBEDTLS_PRIVATE(wendy_defer_handshake_input_shrink)=owned &&
        !heap_caps_get_total_size(MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);
#else
    c->config.MBEDTLS_PRIVATE(wendy_defer_handshake_input_shrink)=owned!=NULL;
#endif
#endif
    mbedtls_ssl_conf_cert_profile(&c->config, wendy_pki_certificate_profile());
    mbedtls_ssl_conf_verify(&c->config, certificate_policy, c);
    mbedtls_ssl_conf_ca_chain(&c->config, &c->roots, NULL);
    mbedtls_ssl_conf_min_tls_version(&c->config, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_max_tls_version(&c->config, MBEDTLS_SSL_VERSION_TLS1_3);
    /* Each connection authenticates certificates. Do not negotiate unused
     * resumption PSKs or require callers to handle post-handshake tickets. */
    mbedtls_ssl_conf_tls13_key_exchange_modes(&c->config,
        MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL);
    bool der_input=owned && owned->read_der;
    bool defer_records=verify_at && der_input;
    if (der_input && (!verify_at || cert.data || owned->certificate_size || pki_key_encoding(key,key_size)))
        return configure_failed("DER identity input",MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
    uint8_t local_path_hash[32];unsigned cached_count=0;
    bool cacheable=false,reused=false;
    if(verify_at && der_input && stream_identity){
        c->presented_chain=pki_owned_calloc(1,sizeof *c->presented_chain);
        if(c->presented_chain && !own_path_hash(owned,roots,principal,c->presented_chain,local_path_hash)){
            cacheable=true;
            reused=own_path_reuse(local_path_hash,verify_at,&c->device_expires,&cached_count);
        }else{pki_owned_free(c->presented_chain);c->presented_chain=NULL;}
    }
    if(der_input && owned->reserve_records_first && !c->setup_input_reservation) {
        c->setup_input_reservation=pki_tls_input_take(input_reserve);
        c->setup_input_capacity=input_reserve;
        if(!c->setup_input_reservation)
            ESP_LOGI("wendy_pki","local DER parse without preferred receive reservation");
    }
    if (!der_input && verify_at && (!owned || !owned->certificate_size || !cert.data ||
        owned->certificate_size != cert.size ||
        pki_identity_encoding(cert.data,cert.size,key,key_size)))
        return configure_failed("identity encoding", MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
    if (key || cert.data || der_input) {
        if (!key || (!cert.data && !der_input))
            return configure_failed("identity input", MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
        r = der_input ? parse_owned_der(&c->certificate,owned,reused) :
            owned ? parse_owned_certificates(&c->certificate,owned) :
            pki_parse_certificate_bundle(&c->certificate,cert.data,cert.size,false);
        /* The preferred record-buffer hole can itself prevent decoding a
         * valid local PQC chain on SRAM-only devices with two live carriers.
         * DER sources are indexed, so release this optional reservation and
         * retry from a clean chain. All path/key checks still run below, and
         * final record storage must still be allocated before any handshake.
         * PEM input is consumed while parsing and cannot be replayed here. */
        if (der_input && c->setup_input_reservation &&
            (r == PSA_ERROR_INSUFFICIENT_MEMORY ||
             r == MBEDTLS_ERR_X509_ALLOC_FAILED || r == MBEDTLS_ERR_PK_ALLOC_FAILED)) {
            ESP_LOGI("wendy_pki", "retry local DER parse without receive reservation");
            mbedtls_x509_crt_free(&c->certificate);
            mbedtls_x509_crt_init(&c->certificate);
            pki_tls_input_return(c->setup_input_reservation,c->setup_input_capacity); c->setup_input_reservation=NULL;
            pki_tls_input_discard_cached();
            r=parse_owned_der(&c->certificate,owned,reused);
        }
        if (r) return configure_failed("identity certificate parsing", r);
        if(cacheable){
            unsigned index=0;
            for(const mbedtls_x509_crt *part=&c->certificate;part;part=part->next){
                uint8_t hash[32];
                if(index>=c->presented_chain->count ||
                   part->raw.len!=c->presented_chain->part[index].size ||
                   wendy_pki_sha256(part->raw.p,part->raw.len,hash) ||
                   memcmp(hash,c->presented_chain->part[index].hash,32))
                    return configure_failed("local source binding",MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
                index++;
            }
            if(index!=(reused ? 1:c->presented_chain->count))
                return configure_failed("local source count",MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
        }
        r = mbedtls_pk_parse_key(&c->key, key, key_size, NULL, 0);
        if (r) return configure_failed("private key parsing", r);
        r = mbedtls_pk_check_pair(&c->certificate.pk, &c->key);
        if (r) return configure_failed("certificate/key match", r);
        r = mbedtls_ssl_conf_own_cert(&c->config, &c->certificate, &c->key);
        if (r) return configure_failed("mbedtls_ssl_conf_own_cert", r);
    }
    /* The key and chain have been parsed and matched. Release the large PEM
     * copy before reserving TLS record buffers or collecting the peer chain. */
    if (owned) {
        if (owned->trust) {
            if (owned->trust != roots.data || owned->trust_capacity != roots.size+1 ||
                owned->trust[roots.size] != 0)
                return configure_failed("owned CA input", MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
            if(!reserve_raw_roots(c,owned->trust,owned->trust_capacity))
                return configure_failed("owned CA budget",MBEDTLS_ERR_X509_ALLOC_FAILED);
            c->mesh_roots = owned->trust;
            c->mesh_roots_size = roots.size;
            owned->trust = NULL;
        }
    }
    if(owned && owned->public_chain) {
        struct pki_public_chain *public=owned->public_chain;
        if(!verify_at || !owned->read_der || !public->count || public->count>8 ||
            !public->read || !public->destroy)
            return configure_failed("public DER source",MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
        unsigned count=0;
        if(cacheable){
            if(public->count!=c->presented_chain->count)
                return configure_failed("public DER count",MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
            for(;count<public->count;count++) {
                if(memcmp(c->presented_chain->part[count].hash,public->hashes[count],32))
                    return configure_failed("public DER binding",MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
                if(public->sizes)public->sizes[count]=(uint32_t)c->presented_chain->part[count].size;
            }
        }else for(const mbedtls_x509_crt *part=&c->certificate;part && part->raw.len;part=part->next) {
            uint8_t hash[32];
            if(count>=public->count || wendy_pki_sha256(part->raw.p,part->raw.len,hash) ||
                memcmp(hash,public->hashes[count++],32))return configure_failed("public DER binding",MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
            if(public->sizes)public->sizes[count-1]=(uint32_t)part->raw.len;
        }
        if(count!=public->count)return configure_failed("public DER count",MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
        if(public->load_trust && wendy_pki_sha256(roots.data,roots.size,public->trust_hash))
            return configure_failed("public trust binding",MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
        c->public_chain=public;owned->public_chain=NULL;
    }
    release_identity_input(owned);
    /* Prefer one final-sized input allocation over a 16KiB buffer followed
     * by a simultaneous 24KiB replacement during certificate reassembly. */
    if (verify_at && !defer_records) {
        pki_tls_input_return(c->setup_input_reservation,c->setup_input_capacity);c->setup_input_reservation=NULL;
        r = setup_reserved_records(c,input_reserve);
        if (r) return configure_failed("reserved mbedtls_ssl_setup", r);
    } else if (!verify_at) {
        /* Allocate contiguous record storage before root objects divide the
         * remaining heap; HTTPS uses the ordinary configured record limit. */
#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
        bool small_initial=!server && !key && !cert.data;
        r = small_initial ? mbedtls_ssl_setup_small_input(&c->ssl,&c->config) :
                            mbedtls_ssl_setup(&c->ssl,&c->config);
#else
        r = mbedtls_ssl_setup(&c->ssl, &c->config);
#endif
        if (r) return configure_failed("mbedtls_ssl_setup", r);
#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
        if (small_initial) {
            /* Timestamp/enrollment HTTPS sends no device certificate. Keep
             * its initial receive allocation small, growing to actual valid
             * records instead of reserving16KiB during CA verification. */
        }
#endif
    }
    if (c->mesh_roots) {
        r = parse_owned_roots(c,&roots);
    } else {
        r=pki_parse_certificate_bundle(&c->roots,roots.data,roots.size,false);
    }
    if (r) return configure_failed("CA bundle parsing", r);
    /* The exact pinned anchor is available independently in roots. Omit its
     * duplicate from the local presentation before verifying the selected
     * path; the verifier still checks the anchor's policy and expiry. */
    if (owned) trim_presented_anchor(c);
    /* Place the small presentation metadata while the receive-buffer hole
     * is still reserved, so this allocation cannot fragment that hole. */
    if (stream_identity && c->certificate.next && !c->presented_chain) {
        c->presented_chain=pki_owned_calloc(1,sizeof *c->presented_chain);
        if (!c->presented_chain)
            return configure_failed("own presentation metadata",MBEDTLS_ERR_SSL_ALLOC_FAILED);
    }
    /* A cold local path borrows the reservation for verification workspace.
     * A current memoized path keeps the early allocation for direct adoption
     * by TLS. Neither path attaches a BIO before all identity checks pass. */
    if (defer_records && !reused) {
        pki_tls_input_return(c->setup_input_reservation,c->setup_input_capacity); c->setup_input_reservation=NULL;
        pki_tls_input_discard_cached();
    }
    /* A current memoized local path has no verification workspace to borrow.
     * Preserve its early input allocation and hand ownership to TLS directly. */
    if (verify_at && !reused && (!principal ||
        pki_verify_parsed_identity(&c->certificate, &c->key, roots.data, roots.size, &c->roots,
                                  principal, verify_at, &c->device_expires)))
        return configure_failed("local identity path", MBEDTLS_ERR_X509_CERT_VERIFY_FAILED);
    /* No issuer is discarded until the entire exact local path, principal,
     * private key and pinned roots have passed independent verification. */
    if (stream_identity && (!verify_at || !read_der ||
        pin_presented_chain(c,read_der,read_range,der_context,cached_count)))
        return configure_failed("verified own presentation",MBEDTLS_ERR_SSL_INTERNAL_ERROR);
    if(cacheable){
        if(!reused)own_path_remember(local_path_hash,verify_at,c->device_expires,
            c->presented_chain ? c->presented_chain->count:1);
        ESP_LOGI("wendy_pki","local certificate path: %s",reused ? "reused":"verified and cached");
    }
    if (defer_records) {
        r=setup_reserved_records(c,input_reserve);
        if (r) return configure_failed("post-verification reserved mbedtls_ssl_setup",r);
    }
    mbedtls_ssl_set_bio(&c->ssl, c, io_send, io_recv, NULL);
    return 0;
}
    bool idle_read = true;
    while (n) {
        if (wendy_pki_reset_in_progress()) return -1;
        if (esp_timer_get_time() >= deadline)
            return n == size && idle_read ? READ_ALL_IDLE_TIMEOUT : -1;
        int got = connection_read(c, out, n);
        if (got > 0) { out += got; n -= got; }
        else {
            if (!got) return -1;
            /* A readiness hint can cross the deadline before the next loop.
             * Keep WANT_WRITE failures distinct from an empty idle read. */
            idle_read = got == MBEDTLS_ERR_SSL_WANT_READ;
