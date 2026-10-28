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

struct configure_cpu {
    wendy_pki_connection *c;int server;const uint8_t *key;size_t key_size;
    struct wendy_conf_span cert,roots;struct pki_tls_owned_identity *owned;
    const char *principal;time_t verify_at;bool consume,streamed;int result;
};
static void configure_cpu(void *context)
{
    struct configure_cpu *j=context;
    wendy_net_memory_scope_t previous=connection_scope(j->c);
    j->result=configure_direct(j->c,j->server,j->key,j->key_size,j->cert,j->roots,
        j->owned,j->principal,j->verify_at,j->consume,j->streamed);
    wendy_net_memory_scope_leave(previous);
}
static int configure(wendy_pki_connection *c,int server,const uint8_t *key,size_t key_size,
    struct wendy_conf_span cert,struct wendy_conf_span roots,struct pki_tls_owned_identity *owned,
    const char *principal,time_t verify_at,bool consume,bool streamed)
{
    struct configure_cpu j={c,server,key,key_size,cert,roots,owned,principal,verify_at,consume,streamed,MBEDTLS_ERR_SSL_INTERNAL_ERROR};
    return wendy_pki_work_run(configure_cpu,&j) ? MBEDTLS_ERR_SSL_INTERNAL_ERROR:j.result;
}
static int claim_legacy_handshake(wendy_pki_connection *c,int64_t deadline)
{
#if ESP_PLATFORM && CONFIG_WENDY_NET_PEER
    if(wendy_pki_reset_in_progress() || esp_timer_get_time()>=deadline)return -1;
    while(!wendy_pki_handshake_claim(c)){
        if(wendy_pki_reset_in_progress() || esp_timer_get_time()>=deadline)return -1;
        vTaskDelay(1);
    }
#else
    (void)c;(void)deadline;
#endif
    return 0;
}
/* Keep an elapsed idle deadline distinct from EOF, reset and transport errors.
 * Existing I/O callers treat every nonzero wait result as failure. */
enum { SOCKET_WAIT_TIMEOUT = -2 };
static int wait_socket(wendy_pki_connection *c, int error, int64_t deadline)
{
    if (wendy_pki_reset_in_progress()) return -1;
    if (error != MBEDTLS_ERR_SSL_WANT_READ && error != MBEDTLS_ERR_SSL_WANT_WRITE)
        return -1;
#if ESP_PLATFORM
    /* A writable low-water mark can race a partial record retry. The carrier
     * and loopback relay run at lower priority than the handshake worker. */
    if (error==MBEDTLS_ERR_SSL_WANT_WRITE && !c->stream.wait) vTaskDelay(1);
#endif
    int64_t left = deadline - esp_timer_get_time();
    if (left <= 0)
        return SOCKET_WAIT_TIMEOUT;
    if (c->stream.wait) {
        if (wendy_pki_reset_in_progress()) return -1;
        int result=c->stream.wait(c->stream.context, error == MBEDTLS_ERR_SSL_WANT_WRITE, deadline);
        /* The stream contract merges timeout/disconnect into -1. Preserve
         * that failure even at the renewal boundary. Only a successful retry
         * hint may become an elapsed wait, with its TLS direction retained. */
        if(result || wendy_pki_reset_in_progress())return -1;
        return esp_timer_get_time()>=deadline ? SOCKET_WAIT_TIMEOUT:0;
    }
    fd_set rd, wr;
    FD_ZERO(&rd);
    FD_ZERO(&wr);
    if (error == MBEDTLS_ERR_SSL_WANT_READ)
        FD_SET(c->fd, &rd);
    else
        FD_SET(c->fd, &wr);
    struct timeval tv = {left / 1000000, left % 1000000};
    int ready = select(c->fd + 1, &rd, &wr, NULL, &tv);
    return ready > 0 ? 0 : ready == 0 ? SOCKET_WAIT_TIMEOUT : -1;
}
static int detach_socket(wendy_pki_connection *c)
{
    if (!c || c->stream.read || c->fd < 0) return -1;
    int64_t deadline = esp_timer_get_time() + 10000000;
    unsigned char byte;
    for (;;) {
        int n = connection_read(c, &byte, 1);
        if (n == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) break;
        // Reject TCP EOF and application data after the upgrade.
        if (n >= 0 || wait_socket(c, n, deadline)) return -1;
    }
    int n;
    while ((n = mbedtls_ssl_close_notify(&c->ssl)) != 0)
        if (wait_socket(c, n, deadline)) return -1;
    int fd = c->fd; c->fd = -1;
    return fd;
}
int wendy_pki_detach(wendy_pki_connection *c)
{
    if(!c)return -1;
    wendy_net_memory_scope_t previous=connection_scope(c);
    int fd = detach_socket(c);
    if (fd >= 0)
        wendy_pki_close(c);
    wendy_net_memory_scope_leave(previous);
    return fd;
}
static int bind_interface(int fd, const char* interface)
{
    if (!interface) return 0;
#if ESP_PLATFORM
    struct ifreq request = { 0 };
    if (strlen(interface) >= sizeof request.ifr_name) return -1;
    snprintf(request.ifr_name, sizeof request.ifr_name, "%s", interface);
    return setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &request, sizeof request);
#else
    (void)fd;
    return -1;
#endif
}
static int direct_resolve(const char* host, const char* resolver, const char* interface,
    char address[INET_ADDRSTRLEN])
{
    if (!resolver || !resolver[0] || !interface || !interface[0]) return -1;
    struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_DGRAM,
        .ai_flags = AI_NUMERICHOST }, *server = NULL;
    if (getaddrinfo(resolver, "53", &hints, &server)) return -1;
    int fd = socket(server->ai_family, server->ai_socktype, server->ai_protocol);
    uint8_t query[272], reply[1024], ip[4];
    /* The connected UDP socket also binds the response to the selected DNS
     * server and the socket's ephemeral source port. */
    uint16_t id;
    size_t size = psa_generate_random((uint8_t*)&id, sizeof id) == PSA_SUCCESS
        ? pki_dns_query(query, host, id) : 0;
    int result = -1;
    if (fd < 0 || fd >= FD_SETSIZE || !size || bind_interface(fd, interface)) goto done;
    struct timeval timeout = { .tv_sec = 5 };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout)
        || setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout)
        || connect(fd, server->ai_addr, server->ai_addrlen)
        || send(fd, query, size, 0) != (ssize_t)size) goto done;
    ssize_t n = recv(fd, reply, sizeof reply, 0);
    if (n > 0 && !pki_dns_answer(query, size, reply, n, ip)
        && inet_ntop(AF_INET, ip, address, INET_ADDRSTRLEN)) result = 0;
done:
    if (fd >= 0) close(fd);
    freeaddrinfo(server);
    return result;
}
/* Only the opt-in borrower lengthens ordinary Cloud traffic. A probe bound to
 * a physical interface retains the direct-path budget. Neither budget slides. */
static int64_t network_budget_us(bool gateway, const char *interface)
{
    (void)interface;
    return gateway ? INT64_C(60000000) : INT64_C(15000000);
}

static int finish_mesh(wendy_pki_connection *c,const char *tenant,const char *device,
    const char *router,bool gateway,const char *protocol,time_t self_verified_until,
    struct wendy_conf_span roots,bool native_router)
{
    (void)gateway;
    {
        const char* alpn = mbedtls_ssl_get_alpn_protocol(&c->ssl);
        const mbedtls_x509_crt* peer = mbedtls_ssl_get_peer_cert(&c->ssl);
        char expected_prefix[70];
        snprintf(expected_prefix,sizeof expected_prefix,"spiffe://wendy.sh/tenant/%s/device/",tenant);
        enum wendy_peer_role role=peer ? wendy_peer_auth_role(peer,tenant):WENDY_PEER_ROLE_NONE;
        /* A primary operator terminates the ordinary incoming app protocol.
         * It has no enrolled UUID: keep its typed role and never put its URI in
         * mesh_peer. Carrier and outgoing device pins remain device-only. */
        bool operator_app=role==WENDY_PEER_ROLE_OPERATOR && !gateway && !router &&
            protocol && !strcmp(protocol,"wendy-app-mesh-tls/1") &&
            c->config.MBEDTLS_PRIVATE(endpoint)==MBEDTLS_SSL_IS_SERVER;
        if (!alpn || !protocol || strcmp(alpn,protocol) || !peer
            || wendy_pki_certificate_policy(peer,false) ||
               (role!=WENDY_PEER_ROLE_DEVICE && !operator_app))
            goto fail;
        unsigned count = 0;
        for (const mbedtls_x509_sequence* a = &peer->subject_alt_names; !operator_app && a && a->buf.p; a = a->next)
        {
            mbedtls_x509_subject_alternative_name san;
            if (mbedtls_x509_parse_subject_alt_name(&a->buf, &san)
                || san.type != MBEDTLS_X509_SAN_UNIFORM_RESOURCE_IDENTIFIER)
                continue;
            const unsigned char *uri=san.san.unstructured_name.p;
            if (san.san.unstructured_name.len != 105 ||
                memcmp(uri,expected_prefix,69) || !wendy_identity_uuid(uri+69,36)) goto fail;
            memcpy(c->mesh_peer,uri+69,36);
            c->mesh_peer[36]=0;
            if (!strcmp(c->mesh_peer,device) || (router && strcmp(c->mesh_peer,router))) goto fail;
            count++;
        }
        if (!operator_app && count != 1)
            goto fail;
        time_t now = time(NULL);
        if (!c->operator_expires || c->operator_expires <= now) goto fail;
        /* The native caller just verified these exact key/certificate/trust
         * inputs under identity_lock. Preserve its full-path expiry without
         * parsing a second local chain beside the live peer chain. */
        if (self_verified_until) {
            if (self_verified_until <= now) goto fail;
        } else {
            const uint8_t *der[8]; size_t sizes[8], cert_count = 0;
            for (const mbedtls_x509_crt *cert = &c->certificate; cert && cert->raw.len; cert=cert->next) {
                if (cert_count == 8) goto fail;
                der[cert_count] = cert->raw.p; sizes[cert_count++] = cert->raw.len;
            }
            struct wendy_pki_mesh_peer* self = pki_owned_calloc(1, sizeof *self);
            bool verified = self && !wendy_pki_mesh_chain(der, sizes, cert_count, roots.data, roots.size, tenant, now, self)
                && !strcmp(self->device, device);
            if (verified) self_verified_until = self->expires;
            pki_owned_free(self);
            if (!verified) goto fail;
        }
        if (self_verified_until < c->operator_expires) c->operator_expires = self_verified_until;
        c->device_expires=self_verified_until;
        if (pki_limit_session(c,now,esp_timer_get_time())) goto fail;
        c->peer_role = role;
        if (protocol && !strcmp(protocol,"wendy-app-mesh-tls/1")) {
            release_verified_paths(c);
        } else if (native_router) {
            if(c->public_chain) {
                struct wendy_pki_mesh_peer verified;
                if(wendy_pki_mesh_authenticated_peer(c,&verified))goto fail;
                c->authenticated_peer=pki_owned_malloc(sizeof verified);
                if(!c->authenticated_peer)goto fail;
                *c->authenticated_peer=verified;
                release_session_certificates(c);
                if (c->public_chain->load_trust)
                {
                    c->lazy_trust = true;
                    mbedtls_ssl_conf_ca_chain(&c->config, NULL, NULL);
                    mbedtls_x509_crt_free(&c->roots);
                    release_mesh_roots(c);
                    c->mesh_roots = NULL;
                    c->mesh_roots_size = 0;
                }
                else if (c->roots.raw.len && !c->roots.next)
                {
                    uint8_t hash[32];
                    if (wendy_pki_sha256(c->roots.raw.p, c->roots.raw.len,
                                         hash))
                        goto fail;
                    for (unsigned i = 0; i < c->public_chain->count; i++)
                        if (!memcmp(hash, c->public_chain->hashes[i], 32))
                        {
                            c->public_anchor = (uint8_t)(i + 1);
                            mbedtls_ssl_conf_ca_chain(&c->config, NULL, NULL);
                            mbedtls_x509_crt_free(&c->roots);
                            break;
                        }
                }
#if ESP_PLATFORM && CONFIG_WENDY_NET_PEER
                ESP_LOGI("wendy_pki",
                         "router proof memory: own_parts=%u lazy_anchor=%u "
                         "lazy_trust=%u free=%u largest=%u",
                         c->public_chain->count, (unsigned)c->public_anchor,
                         (unsigned)c->lazy_trust,
                         (unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT),
                         (unsigned)heap_caps_get_largest_free_block(
                             MALLOC_CAP_8BIT));
#endif
            }
            /* Routing proofs need the verified public certificates, not a
             * certificate-flight-sized idle TLS record buffer. Grow back on
             * larger encrypted application records without changing limits. */
            c->compact_records=true;
#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
            mbedtls_ssl_release_handshake_buffer(&c->ssl);
            mbedtls_ssl_compact_input_buffer(&c->ssl);
#endif
        }
    }
    return 0;
fail:
    return -1;
}

static int open_tls(const char* host, unsigned port, const uint8_t* key, size_t key_size,
    struct wendy_conf_span cert, struct wendy_conf_span roots, wendy_pki_connection** out, const char* tenant,
    const char* device, const char* router, const struct wendy_pki_stream* stream, bool server,
    bool gateway, const char* interface, const char* resolver, const char* protocol, struct pki_tls_owned_identity *owned, int *accepted_fd)
{
    if (out)
        *out = NULL;
    bool mesh = tenant != NULL;
    if(mesh && !protocol)return -1;
    bool native_stream=stream && owned && protocol && !strcmp(protocol,"wendy-local-mesh-ble/2");
    bool incoming = accepted_fd && *accepted_fd >= 0;
    if (!out || !roots.data || !roots.size
        || (incoming && (!server || !mesh || stream || !protocol))
        || (!incoming && (stream ? (!stream->read || !stream->write || !stream->wait ||
                         (!mesh && (server || key || cert.data || owned || !host || !host[0] ||
                                    strlen(host)>253 || !port || port>65535)))
                   : (!host || !host[0] || strlen(host) > 253 || !port || port > 65535))))
        return -1;
    bool discover_peer = mesh && stream && !server && !gateway && !router;
    if (mesh
        && (!device || (!incoming && !native_stream && !discover_peer && !router) || !wendy_identity_uuid((const unsigned char*)tenant, strlen(tenant))
            || !wendy_identity_uuid((const unsigned char*)device, strlen(device))
            || (router && (!wendy_identity_uuid((const unsigned char*)router, strlen(router))
                           || !strcmp(device, router)))))
        return -1;
    time_t self_verified_until = owned ? owned->verified_until : 0;
    wendy_pki_connection* c = pki_owned_calloc(1, sizeof *c);
    if (!c)
        return -1;
    c->allocation_scope=wendy_net_memory_scope_current();
    c->fd = incoming ? *accepted_fd : -1;
    if (incoming) *accepted_fd = -1;
    const char* stage = "TLS setup";
    int tls_error = 0;
    struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM },
                    *addresses = NULL;
    if (incoming && (c->fd >= FD_SETSIZE ||
        fcntl(c->fd, F_SETFL, fcntl(c->fd,F_GETFL,0)|O_NONBLOCK) < 0)) goto fail;
    if(claim_legacy_handshake(c,esp_timer_get_time()+INT64_C(60000000)))goto fail;
    /* Parse local credentials before starting the broker's TCP deadline. */
    char self_principal[106];
    if (mesh) snprintf(self_principal, sizeof self_principal,
        "spiffe://wendy.sh/tenant/%s/device/%s", tenant, device);
    time_t verify_at = owned ? owned->verify_at : 0;
    bool compact=owned && protocol && !strcmp(protocol,"wendy-app-mesh-tls/1");
    bool native_router=owned && protocol && !strcmp(protocol,"wendy-local-mesh-ble/2");
    bool stream_identity=owned && owned->read_der &&
        (compact || (native_router && owned->public_chain));
    if (configure(c, server, key, key_size, cert, roots, owned,
                  mesh ? self_principal : NULL, verify_at,compact || native_router,
                  stream_identity)) goto fail;
    if (verify_at) self_verified_until = c->device_expires;
    if (mesh)
    {
        static const char* const app_protocols[] = { "wendy-app-mesh-tls/1", NULL };
        static const char* const router_protocols[] = { "wendy-local-mesh-ble/2", NULL };
        const char* const* protocols = !strcmp(protocol,"wendy-app-mesh-tls/1") ? app_protocols : router_protocols;
        if (configure_mesh_alpn(c, protocols))
            goto fail;
        /* Mesh identity is the exact SPIFFE principal, checked below after
         * mandatory CA verification. It is independent of the dial address. */
        if (mbedtls_ssl_set_hostname(&c->ssl, NULL))
            goto fail;
        memcpy(c->mesh_tenant, tenant, 37);
        memcpy(c->mesh_device, device, 37);
        if (!c->mesh_roots && !compact &&
            (!owned || !c->roots.raw.len || c->roots.next)) {
            c->mesh_roots = pki_owned_malloc(roots.size);
            c->mesh_roots_prefixed = true;
            if (!c->mesh_roots)
                goto fail;
            memcpy(c->mesh_roots, roots.data, roots.size);
            c->mesh_roots_size = roots.size;
        }
    }
    else if (mbedtls_ssl_set_hostname(&c->ssl, host))
        goto fail;
    int64_t deadline = esp_timer_get_time() + 30000000;
    if (stream) {
        c->stream = *stream;
        if(native_stream)deadline=esp_timer_get_time()+INT64_C(45000000);
    }
    else if (incoming)
        deadline = esp_timer_get_time() + network_budget_us(false,NULL);
    else
    {
        stage = "DNS";
        char service[6];
        snprintf(service, sizeof service, "%u", port);
        char direct_address[INET_ADDRSTRLEN];
        const char* dial_host = host;
        if (interface) {
            if (direct_resolve(host, resolver, interface, direct_address)) goto fail;
            dial_host = direct_address;
            hints.ai_flags = AI_NUMERICHOST;
        }
        if ((tls_error = getaddrinfo(dial_host, service, &hints, &addresses)) != 0)
            goto fail;
        /* A gateway handshake carries certificate chains over the mesh radio.
         * Keep a finite budget that includes BLE transmission and TCP retries. */
        deadline = esp_timer_get_time() + network_budget_us(gateway, interface);
        stage = "TCP connect";
        for (struct addrinfo* a = addresses; a; a = a->ai_next)
        {
            c->fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
            if (c->fd < 0)
                continue;
            if (c->fd >= FD_SETSIZE)
            {
                close(c->fd);
                c->fd = -1;
                continue;
            }
            if (bind_interface(c->fd, interface)) {
                close(c->fd); c->fd = -1; continue;
            }
            fcntl(c->fd, F_SETFL, O_NONBLOCK);
            int r = connect(c->fd, a->ai_addr, a->ai_addrlen);
            if (r == 0)
                break;
            if (errno == EINPROGRESS && !wait_socket(c, MBEDTLS_ERR_SSL_WANT_WRITE, deadline))
            {
                int e = 0;
                socklen_t n = sizeof e;
                if (!getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &e, &n) && !e)
                    break;
            }
            close(c->fd);
            c->fd = -1;
        }
        freeaddrinfo(addresses);
        addresses = NULL;
        if (c->fd < 0)
            goto fail;
    }
    /* App sessions can traverse BLE hops. A native LAN handshake can also
     * wait behind a sibling BLE setup on the peer's one TLS worker. Keep TCP
     * setup bounded separately, then give either full-peer TLS a finite
     * certificate/worker budget. */
    if(protocol && !strcmp(protocol,"wendy-app-mesh-tls/1"))
        deadline=esp_timer_get_time()+INT64_C(120000000);
    else if(protocol && !strcmp(protocol,"wendy-local-mesh-ble/2"))
        deadline=esp_timer_get_time()+INT64_C(60000000);
    if (protocol && !stream) {
        /* Carrier frames and WAS1 requests write small headers followed by
         * payload records. Do not make either wait for a delayed ACK. */
        int no_delay=1;
        if (setsockopt(c->fd,IPPROTO_TCP,TCP_NODELAY,&no_delay,sizeof no_delay)) goto fail;
    }
    stage = "TLS handshake";
    int r;
    bool compact_server=owned && protocol && !strcmp(protocol,"wendy-app-mesh-tls/1");
    while (c->ssl.MBEDTLS_PRIVATE(state)!=MBEDTLS_SSL_HANDSHAKE_OVER)
    {
        r=handshake_step(c,compact_server);
        if (!r) continue;
        tls_error = r;
        if (wait_socket(c, r, deadline))
            goto fail;
    }
    stage = "certificate verification";
    release_presented_chain(c);
    tls_error = (int)mbedtls_ssl_get_verify_result(&c->ssl);
    if (tls_error)
        goto fail;
    if (mesh && finish_mesh(c,tenant,device,router,gateway,protocol,self_verified_until,
                            roots,native_router)) goto fail;
    wendy_pki_handshake_release(c);
    *out = c;
    return 0;
fail:
    ESP_LOGW("wendy_pki", "TLS peer failed at %s (%s:%u, tls=%d, errno=%d)", stage, incoming ? "accepted" : host, port,
        tls_error, errno);
    if (c && tls_error == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED)
        ESP_LOGW("wendy_pki", "TLS certificate flags=0x%08x",
                 (unsigned)mbedtls_ssl_get_verify_result(&c->ssl));
    if (addresses)
        freeaddrinfo(addresses);
    wendy_pki_close(c);
    return -1;
}
int pki_tls_connect(const char* host, unsigned port, const uint8_t* key, size_t key_size,
    struct wendy_conf_span cert, struct wendy_conf_span roots, wendy_pki_connection** out)
{
    return open_tls(host, port, key, key_size, cert, roots, out, NULL, NULL, NULL, NULL, false, false, NULL, NULL, NULL, NULL, NULL);
}
int pki_tls_bound_connect(const char* host, unsigned port, const char* interface, const char* resolver,
    const uint8_t* key, size_t key_size, struct wendy_conf_span cert,
    struct wendy_conf_span roots, wendy_pki_connection** out)
{
    if (!interface || !interface[0]) return -1;
    return open_tls(host, port, key, key_size, cert, roots, out,
        NULL, NULL, NULL, NULL, false, false, interface, resolver, NULL, NULL, NULL);
}
/* Readiness is only a hint. Stream callbacks may wake spuriously. */
int wendy_pki_wait(wendy_pki_connection* c, bool writing, int64_t deadline)
{
    if (!c || wendy_pki_reset_in_progress()) return -1;
    int64_t now=esp_timer_get_time();
    if ((c->session_deadline_us && now>=c->session_deadline_us) ||
        (c->relay_expires_us && now>=c->relay_expires_us)) return -1;
    if (c->session_deadline_us && deadline>c->session_deadline_us) deadline=c->session_deadline_us;
    if (c->relay_expires_us && deadline>c->relay_expires_us) deadline=c->relay_expires_us;
    if (!writing && wendy_pki_pending(c)) return 1;
    int64_t left = deadline - esp_timer_get_time();
    if (left <= 0) return 0;
    if (c->stream.wait)
        return c->stream.wait(c->stream.context, writing, deadline) < 0 ? -1 : 1;
    if (c->fd < 0 || c->fd >= FD_SETSIZE) return -1;
    fd_set set;
    FD_ZERO(&set);
    FD_SET(c->fd, &set);
    struct timeval timeout = { left / 1000000, left % 1000000 };
    return select(c->fd + 1, writing ? NULL : &set, writing ? &set : NULL, NULL, &timeout);
}
/* RAM-only query. The actor checks its fine-grained connection loan before
 * inspecting this immutable key type; actual signing remains on the worker. */
size_t wendy_pki_artifact_signature_capacity(wendy_pki_connection *c)
{
    return c && c->mesh_deadline_us && esp_timer_get_time()<c->mesh_deadline_us &&
        !wendy_pki_reset_in_progress() ? pki_artifact_signature_capacity(&c->key):0;
}
int wendy_pki_artifact_sign(wendy_pki_connection *c,unsigned kind,const char *principal,
    const void *body,size_t size,uint8_t *signature,size_t capacity,size_t *written)
{
    if(!c || !principal || strlen(principal)!=105 ||
       memcmp(principal,"spiffe://wendy.sh/tenant/",25) || memcmp(principal+61,"/device/",8) ||
       memcmp(principal+25,c->mesh_tenant,36) || strcmp(principal+69,c->mesh_device) ||
       !c->mesh_deadline_us || esp_timer_get_time()>=c->mesh_deadline_us ||
       wendy_pki_reset_in_progress())return -1;
    return pki_artifact_sign(&c->key,kind,principal,body,size,signature,capacity,written);
}
int wendy_pki_mesh_sign_digest(wendy_pki_connection* c,const char* principal,const uint8_t hash[32],uint8_t signature[80],size_t* signature_size)
{
    if (!c || !principal || strlen(principal) != 105 || memcmp(principal + 25, c->mesh_tenant, 36)
        || strcmp(principal + 69, c->mesh_device) || !signature || !signature_size
        || !c->mesh_deadline_us || esp_timer_get_time() >= c->mesh_deadline_us
        || wendy_pki_reset_in_progress())
        return -1;
    if(pki_artifact_signature_capacity(&c->key)!=80)return -1;
    return mbedtls_pk_sign(
                &c->key, MBEDTLS_MD_SHA256, hash, 32, signature, 80, signature_size)
        ? -1
        : 0;
}
int wendy_pki_mesh_sign(wendy_pki_connection *c,const char *principal,const void *body,size_t size,uint8_t signature[80],size_t *written)
{
    uint8_t digest[32];
    return wendy_pki_mesh_digest(principal,body,size,digest) ? -1:wendy_pki_mesh_sign_digest(c,principal,digest,signature,written);
}
static int catalogue_sign(wendy_pki_connection *c,const char *principal,const void *body,
    size_t size,uint8_t signature[80],size_t *signature_size,
    int (*digest)(const void *,size_t,uint8_t[32]))
{
    if(!c || !principal || strlen(principal)!=105 ||
       memcmp(principal,"spiffe://wendy.sh/tenant/",25) || memcmp(principal+61,"/device/",8) ||
       memcmp(principal+25,c->mesh_tenant,36) || strcmp(principal+69,c->mesh_device) ||
       !signature || !signature_size || !c->mesh_deadline_us ||
       esp_timer_get_time()>=c->mesh_deadline_us || wendy_pki_reset_in_progress())return -1;
    uint8_t hash[32];
    return digest(body,size,hash) ||
        mbedtls_pk_sign(&c->key,MBEDTLS_MD_SHA256,hash,sizeof hash,signature,80,signature_size) ? -1:0;
}
int wendy_pki_service_sign(wendy_pki_connection *c,const char *principal,const void *body,
    size_t size,uint8_t signature[80],size_t *signature_size)
{return catalogue_sign(c,principal,body,size,signature,signature_size,wendy_pki_service_digest);}
int wendy_pki_inventory_sign(wendy_pki_connection *c,const char *principal,const void *body,
    size_t size,uint8_t signature[80],size_t *signature_size)
{return catalogue_sign(c,principal,body,size,signature,signature_size,wendy_pki_inventory_digest);}
static struct wendy_conf_span mesh_trust(const wendy_pki_connection *c)
{
    if(!c)return (struct wendy_conf_span){0};
    if(c->mesh_roots)return (struct wendy_conf_span){c->mesh_roots,c->mesh_roots_size};
    if(c->roots.raw.len && !c->roots.next)
        return (struct wendy_conf_span){c->roots.raw.p,c->roots.raw.len};
    return (struct wendy_conf_span){0};
}
static bool mesh_has_trust(const wendy_pki_connection *c)
{
    return c && (c->lazy_trust || c->public_anchor || mesh_trust(c).size);
}
struct own_part
{
    const uint8_t *data;
    uint8_t *owned;
    size_t size;
};
static int own_part(wendy_pki_connection *c, unsigned index,
                    struct own_part *part)
{
    *part = (struct own_part){0};
    if (index >= 8)
        return -1;
    if (c->public_chain)
    {
        struct pki_public_chain *chain = c->public_chain;
        if (index >= chain->count)
            return 0;
        uint8_t hash[32];
        int loaded=chain->read(chain->context,index,&part->owned,&part->size);
        if(loaded==-2)return -2;
        if (loaded != 1 ||
            !part->owned || !part->size || part->size > 65536 ||
            wendy_pki_sha256(part->owned, part->size, hash) ||
            memcmp(hash, chain->hashes[index], 32))
        {
            pki_owned_free(part->owned);
            *part = (struct own_part){0};
            return -1;
        }
        part->data = part->owned;
        return 1;
    }
    const mbedtls_x509_crt *cert = &c->certificate;
    for (unsigned i = 0; cert && cert->raw.len && i < index; i++)
        cert = cert->next;
    if (!cert || !cert->raw.len)
        return 0;
    part->data = cert->raw.p;
    part->size = cert->raw.len;
    return 1;
}
static unsigned own_count(wendy_pki_connection *c)
{
    if (c->public_chain)
        return c->public_chain->count;
    unsigned count = 0;
    for (const mbedtls_x509_crt *cert = &c->certificate; cert && cert->raw.len;
         cert = cert->next)
        if (++count > 8)
            return 0;
    return count;
}
int wendy_pki_mesh_public_index_snapshot(wendy_pki_connection *c,
    const struct wendy_pki_mesh_identity *clock,struct wendy_pki_mesh_public_index *out)
{
    if(!out)return -1;
    *out=(struct wendy_pki_mesh_public_index){0};
    if(!c || !clock || !mesh_has_trust(c) || !c->public_chain ||
       !c->public_chain->metadata || strcmp(c->mesh_tenant,clock->tenant) ||
       strcmp(c->mesh_device,clock->device) ||
       c->public_chain->metadata(c->public_chain->context,out))return -1;
    if(!out->count || out->count>8 || out->config_generation!=clock->config_generation)goto fail;
    for(unsigned i=0;i<out->count;i++)
        if(!out->sizes[i] || out->sizes[i]>65536)goto fail;
    return 0;
fail:
    *out=(struct wendy_pki_mesh_public_index){0};return -1;
}
static int own_hash(wendy_pki_connection *c, unsigned index, uint8_t hash[32])
{
    if (c->public_chain)
    {
        if (index >= c->public_chain->count)
            return -1;
        memcpy(hash, c->public_chain->hashes[index], 32);
        return 0;
    }
    struct own_part part;
    int r = own_part(c, index, &part);
    if (r != 1)
        return -1;
    r = wendy_pki_sha256(part.data, part.size, hash);
    pki_owned_free(part.owned);
    return r;
}
int wendy_pki_mesh_fingerprint(wendy_pki_connection *c,uint8_t hash[32])
{
    return !c || !hash || !mesh_has_trust(c) ? -1:own_hash(c,0,hash);
}
int wendy_pki_mesh_describe(wendy_pki_connection *c,char *out,size_t cap)
{
    if(!c || !out || !mesh_has_trust(c) || strlen(c->mesh_device)!=36 || strlen(c->mesh_tenant)!=36)return -1;
    unsigned count=own_count(c);if(!count)return -1;
    char principal[106];snprintf(principal,sizeof principal,"spiffe://wendy.sh/tenant/%s/device/%s",c->mesh_tenant,c->mesh_device);
    struct wn_writer w={.data=(uint8_t*)out,.capacity=cap,.maximum=2048};
    wn_map(&w,2);wn_key(&w,"hashes");wn_array(&w,count);
    for(unsigned i=0;i<count;i++){uint8_t hash[32];if(own_hash(c,i,hash))return -1;wn_bytes(&w,hash,32);}
    wn_key(&w,"principal");wn_text(&w,principal);return wn_finish(&w);
}

int wendy_pki_mesh_part(wendy_pki_connection *c, const uint8_t wanted[32],
                        size_t offset, uint8_t out[1024], size_t *total)
{
    if (!c || !wanted || !out || !total || offset >= 65536 || offset % 1024 ||
        !mesh_has_trust(c))
        return -1;
    unsigned count = own_count(c);
    for (unsigned i = 0; i < count; i++)
    {
        uint8_t hash[32];
        if (own_hash(c, i, hash))
            return -1;
        if (memcmp(hash, wanted, 32))
            continue;
        struct own_part part;
        int loaded=own_part(c,i,&part);
        if(loaded==-2)return -2;
        if(loaded!=1)return -1;
        if (offset >= part.size)
        {
            pki_owned_free(part.owned);
            return -1;
        }
        size_t n = part.size - offset;
        if (n > 1024)
            n = 1024;
        memcpy(out, part.data + offset, n);
        *total = part.size;
        pki_owned_free(part.owned);
        return (int)n;
    }
    return -1;
}
int wendy_pki_mesh_authenticated_peer(wendy_pki_connection *c,
                                      struct wendy_pki_mesh_peer *out)
{
    if (!c || !out || !mesh_has_trust(c) || !c->mesh_peer[0] ||
        c->peer_role != WENDY_PEER_ROLE_DEVICE || !c->session_deadline_us ||
        esp_timer_get_time() >= c->session_deadline_us ||
        wendy_pki_reset_in_progress())
        return -1;
    if (c->authenticated_peer)
    {
        *out = *c->authenticated_peer;
        return 0;
    }
    const mbedtls_x509_crt *peer = mbedtls_ssl_get_peer_cert(&c->ssl);
    if (!peer)
        return -1;
    uint8_t spki[WENDY_PKI_MESH_SPKI_MAX];
    int n=mbedtls_pk_write_pubkey_der((mbedtls_pk_context*)&peer->pk,spki,sizeof spki);
    if (n<=0 || (size_t)n>sizeof spki) return -1;
    *out=(struct wendy_pki_mesh_peer){.expires=c->operator_expires,.spki_size=(size_t)n};
    memcpy(out->device,c->mesh_peer,37);
    memcpy(out->spki,spki+sizeof spki-n,n);
    return 0;
}
int wendy_pki_mesh_verify_bundle(wendy_pki_connection *c,
                                 const uint8_t *const *der, const size_t *sizes,
                                 size_t count, time_t now,
                                 struct wendy_pki_mesh_peer *peer)
{
    if (!mesh_has_trust(c) || !c->mesh_deadline_us ||
        esp_timer_get_time() >= c->mesh_deadline_us ||
        wendy_pki_reset_in_progress())
        return -1;
    if (c->lazy_trust)
    {
        uint8_t *trust_der = NULL, hash[32];
        size_t size = 0;
        mbedtls_x509_crt roots;
        mbedtls_x509_crt_init(&roots);
        int r = -1;
        if (c->public_chain->load_trust(c->public_chain->context, &trust_der,
                                        &size) ||
            !trust_der || !size || size > 16384 || trust_der[0]!=0x30 ||
            wendy_pki_sha256(trust_der, size, hash) ||
            memcmp(hash, c->public_chain->trust_hash, 32))
            goto trust_done;
        if(pki_parse_certificate_bundle(&roots,trust_der,size,true))goto trust_done;
        r = pki_mesh_chain_anchors(der, sizes, count, &roots, c->mesh_tenant,
                                   now, peer);
    trust_done:
        mbedtls_x509_crt_free(&roots);
        free(trust_der);
        return r;
    }
    if (!c->public_anchor)
        return pki_mesh_chain_anchors(der, sizes, count, &c->roots,
                                      c->mesh_tenant, now, peer);
    struct own_part part;
    if (own_part(c, (unsigned)c->public_anchor - 1, &part) != 1)
        return -1;
    mbedtls_x509_crt anchor;
    mbedtls_x509_crt_init(&anchor);
    int r = mbedtls_x509_crt_parse_der_nocopy(&anchor, part.data, part.size);
    if (!r)
        r = pki_mesh_chain_anchors(der, sizes, count, &anchor, c->mesh_tenant,
                                   now, peer);
    mbedtls_x509_crt_free(&anchor);
    pki_owned_free(part.owned);
    return r;
}
int wendy_pki_fd(void *v) { return ((wendy_pki_connection *)v)->fd; }
static ssize_t result(int n)
{
    if (n == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
        return 0;
    if (n >= 0)
        return n;
    int e = n;
    return e == MBEDTLS_ERR_SSL_WANT_READ    ? -2
           : e == MBEDTLS_ERR_SSL_WANT_WRITE ? -3
                                             : -1;
}
static void record_failure(const char *operation,int error)
{
    if (error>=0 || error==MBEDTLS_ERR_SSL_WANT_READ ||
        error==MBEDTLS_ERR_SSL_WANT_WRITE || error==MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
        return;
    ESP_LOGW("wendy_pki","TLS record %s failed: tls=%d",operation,error);
}
ssize_t wendy_pki_read(void* v, void* b, size_t n)
{
    wendy_pki_connection* c = v;
    if (wendy_pki_reset_in_progress()
        || (c->session_deadline_us && esp_timer_get_time() >= c->session_deadline_us)
        || (c->relay_expires_us && esp_timer_get_time() >= c->relay_expires_us))
        return -1;
    wendy_net_memory_scope_t previous=connection_scope(c);
    int received=mbedtls_ssl_read(&c->ssl,b,n);
    record_failure("read",received);
#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
    if (c->compact_records) mbedtls_ssl_compact_input_buffer(&c->ssl);
#endif
    wendy_net_memory_scope_leave(previous);
    return result(received);
}
ssize_t wendy_pki_write(void *v, const void *b, size_t n)
{
    wendy_pki_connection *c = v;
    if (wendy_pki_reset_in_progress() ||
        (c->session_deadline_us && esp_timer_get_time() >= c->session_deadline_us) ||
        (c->relay_expires_us && esp_timer_get_time() >= c->relay_expires_us)) return -1;
    int written=connection_write(c,b,n);
    record_failure("write",written);
    return result(written);
}
bool wendy_pki_pending(wendy_pki_connection *c)
{
    return c && !wendy_pki_reset_in_progress() &&
        (!c->session_deadline_us || esp_timer_get_time() < c->session_deadline_us) &&
        (!c->relay_expires_us || esp_timer_get_time() < c->relay_expires_us) &&
        mbedtls_ssl_get_bytes_avail(&c->ssl) > 0;
}
#include "wendy_pki_http_response.h"
static pthread_mutex_t response_failure_lock = PTHREAD_MUTEX_INITIALIZER;
static char first_issuance_response_failure[192];
static int write_all(wendy_pki_connection *c, const void *b, size_t n, int64_t deadline)
{
    const uint8_t *p = b;
    while (n)
    {
        int r = connection_write(c, p, n);
        if (r > 0)
        {
            p += r;
            n -= r;
        }
        else if (wait_socket(c, r, deadline))
            return -1;
    }
    return 0;
}
static int http_post(const char *url, const char *type, const char *token, const void *body,
                  size_t body_size, const uint8_t *key, size_t key_size, struct wendy_conf_span cert,
                  struct wendy_conf_span roots, uint8_t **response, size_t *response_size,
                  char **lite_authority_header,const struct wendy_pki_stream *stream)
{
    if (lite_authority_header) *lite_authority_header = NULL;
    struct http_parser_url u;
    http_parser_url_init(&u);
    if (!url || strlen(url) > 279 || http_parser_parse_url(url, strlen(url), 0, &u))
        return -1;
    if (!(u.field_set & (1 << UF_SCHEMA)) || u.field_data[UF_SCHEMA].len != 5 ||
        memcmp(url + u.field_data[UF_SCHEMA].off, "https", 5) || !(u.field_set & (1 << UF_HOST)) ||
        u.field_set & ((1 << UF_USERINFO) | (1 << UF_FRAGMENT) | (1 << UF_QUERY)))
        return -1;
    char host[254], path[280];
    size_t hn = u.field_data[UF_HOST].len;
    if (hn == 0 || hn >= sizeof host)
        return -1;
    memcpy(host, url + u.field_data[UF_HOST].off, hn);
    host[hn] = 0;
    if (!(u.field_set & (1 << UF_PATH)))
        return -1;
    snprintf(path, sizeof path, "%.*s", u.field_data[UF_PATH].len, url + u.field_data[UF_PATH].off);
    if (strpbrk(host, "\r\n") || strpbrk(path, "\r\n") || (token && strpbrk(token, "\r\n")))
        return -1;
    wendy_pki_connection *c = NULL;
    unsigned target_port=u.field_set & (1 << UF_PORT) ? u.port:443;
    int connected=stream ? open_tls(host,target_port,NULL,0,(struct wendy_conf_span){0},roots,&c,
        NULL,NULL,NULL,stream,false,false,NULL,NULL,NULL,NULL,NULL) :
        pki_tls_connect(host,target_port,key,key_size,cert,roots,&c);
    if(connected)return -1;
    char authority[264];
    unsigned port = u.field_set & (1 << UF_PORT) ? u.port : 443;
    snprintf(authority, sizeof authority, strchr(host, ':') ? "[%s]:%u" : "%s:%u", host, port);
    int answer = -1;
    char headers[1400];
    int n = snprintf(headers, sizeof headers,
                     "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: %s\r\nContent-Length: "
                     "%zu\r\nConnection: close\r\n%s%s%s\r\n",
                     path, authority, type, body_size, token ? "Authorization: Bearer " : "",
                     token ? token : "", token ? "\r\n" : "");
    /* Small chunks avoid a large realloc and its simultaneous old/new copies.
     * Flatten only after TLS has released certificate and record storage. */
    struct response r = {.capture_lite_authority = lite_authority_header != NULL};
    const char *failure_stage = "request headers";
    int read_error = 0;
    enum http_errno parse_error = HPE_OK;
    unsigned status = 0;
    size_t total = 0;
    if (n < 0 || (size_t)n >= sizeof headers)
        goto done;
    int64_t deadline = esp_timer_get_time() + network_budget_us(false, NULL);
    failure_stage = "request write";
    if (write_all(c, headers, n, deadline) || write_all(c, body, body_size, deadline))
        goto done;
    http_parser parser;
    http_parser_init(&parser, HTTP_RESPONSE);
    parser.data = &r;
    http_parser_settings settings = {.on_body = on_body, .on_message_complete = on_complete,
        .on_header_field = on_header_field, .on_header_value = on_header_value,
        .on_headers_complete = on_headers_complete};
    failure_stage = "response read";
    char buffer[2048];
    while (!r.complete)
    {
        int got = connection_read(c, (unsigned char *)buffer, sizeof buffer);
        if (got == 0) goto done; // TCP EOF without close_notify is a truncated TLS response.
        if (got == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) got = 0;
        if (got < 0)
        {
            read_error = got;
            if (wait_socket(c, got, deadline))
                goto done;
            continue;
        }
        total += got;
        if (total > PKI_MAX_RESPONSE + 8192)
            goto done;
        size_t used = http_parser_execute(&parser, &settings, buffer, got);
        parse_error = HTTP_PARSER_ERRNO(&parser);
        status = parser.status_code;
        if (used != (size_t)got || HTTP_PARSER_ERRNO(&parser) != HPE_OK || (!got && !r.complete))
        {
            failure_stage = "response parse";
            goto done;
        }
    }
    failure_stage = "HTTP status";
    if (parser.status_code != 200) {
        ESP_LOGE("wendy_pki", "PKI HTTP request returned status %u", parser.status_code);
        goto done;
    }
    wendy_pki_close(c);
    c = NULL;
    failure_stage = "response assembly";
    if (response_flatten(&r)) goto done;
    *response = r.bytes;
    *response_size = r.size;
    r.bytes = NULL;
    if (lite_authority_header) {
        *lite_authority_header = r.lite_authority;
        r.lite_authority = NULL;
    }
    answer = 0;
done:
    if (answer)
    {
        ESP_LOGW("wendy_pki", "PKI HTTP failed at %s: status=%u parser=%s tls=%d wire=%u body=%u capacity=%u",
                 failure_stage, status, http_errno_name(parse_error), read_error,
                 (unsigned)total, (unsigned)r.size, (unsigned)r.capacity);
        /* Keep public diagnostics from the original consumed-token failure
         * visible when later 401 retries have displaced it from the console. */
        if (lite_authority_header) {
            pthread_mutex_lock(&response_failure_lock);
            if (status == 200 && !first_issuance_response_failure[0])
                snprintf(first_issuance_response_failure, sizeof first_issuance_response_failure,
                    "%s: parser=%s tls=%d wire=%u body=%u capacity=%u", failure_stage,
                    http_errno_name(parse_error), read_error, (unsigned)total,
                    (unsigned)r.size, (unsigned)r.capacity);
            if (first_issuance_response_failure[0])
                ESP_LOGW("wendy_pki", "First issuance response failure: %s", first_issuance_response_failure);
            pthread_mutex_unlock(&response_failure_lock);
        }
    }
    free(r.lite_authority);
    response_free_chunks(&r);
    free(r.bytes);
    wendy_pki_close(c);
    return answer;
}


int pki_http_post_enrollment(const char *url,const char *type,const char *token,const void *body,
    size_t body_size,const uint8_t *key,size_t key_size,struct wendy_conf_span cert,
    struct wendy_conf_span roots,uint8_t **response,size_t *response_size,char **authority)
{
    return http_post(url,type,token,body,body_size,key,key_size,cert,roots,
        response,response_size,authority,NULL);
}
/* The stream transports HTTPS ciphertext. It supplies no trust, clock,
 * hostname or client identity; normal HTTPS verification remains in open_tls. */
int pki_http_post_stream(const char *url,const char *type,const void *body,size_t body_size,
    struct wendy_conf_span roots,const struct wendy_pki_stream *stream,
    uint8_t **response,size_t *response_size)
{
    if(!stream)return -1;
    return http_post(url,type,NULL,body,body_size,NULL,0,(struct wendy_conf_span){0},roots,
        response,response_size,NULL,stream);
}

int pki_http_post(const char *url, const char *type, const char *token, const void *body,
                  size_t body_size, const uint8_t *key, size_t key_size, struct wendy_conf_span cert,
                  struct wendy_conf_span roots, uint8_t **response, size_t *response_size)
{
    return pki_http_post_enrollment(url, type, token, body, body_size, key, key_size,
        cert, roots, response, response_size, NULL);
}


static int finish_accept_peer(wendy_pki_connection *c,const char *tenant,
    bool allow_device,bool lite,bool owned)
{
    release_presented_chain(c);
    const mbedtls_x509_crt *peer=mbedtls_ssl_get_peer_cert(&c->ssl);
    if(!peer || mbedtls_ssl_get_verify_result(&c->ssl))return -1;
    enum wendy_peer_role role=wendy_pki_certificate_policy(peer,false) ?
        WENDY_PEER_ROLE_NONE:wendy_peer_auth_role(peer,tenant);
    if(role==WENDY_PEER_ROLE_NONE || (!allow_device && role!=WENDY_PEER_ROLE_OPERATOR) ||
       (lite && wendy_pki_verify_lite_operator(peer->raw.p,peer->raw.len,tenant)) ||
       !peer->pk_raw.p || !peer->pk_raw.len ||
       wendy_pki_sha256(peer->pk_raw.p,peer->pk_raw.len,c->operator_spki_hash))return -1;
    unsigned uri_count=0;
    for(const mbedtls_x509_sequence *a=&peer->subject_alt_names;a && a->buf.p;a=a->next){
        mbedtls_x509_subject_alternative_name san;
        if(mbedtls_x509_parse_subject_alt_name(&a->buf,&san) ||
           san.type!=MBEDTLS_X509_SAN_UNIFORM_RESOURCE_IDENTIFIER)continue;
        uri_count++;
        if(wendy_pki_sha256(san.san.unstructured_name.p,san.san.unstructured_name.len,c->operator_hash))return -1;
    }
    if(uri_count!=1)return -1;
    time_t expiry=0;if(pki_parsed_peer_expiry(peer,&expiry))return -1;
    if(!c->operator_expires || expiry<c->operator_expires)c->operator_expires=expiry;
    c->peer_role=role;
    if(owned){
        if(pki_limit_session(c,time(NULL),esp_timer_get_time()))return -1;
        release_verified_paths(c);
    }
    return 0;
}

/* TLS validates the chain, dates and clientAuth usage. LAN may additionally
 * accept a same-tenant device, with its role fixed for the TLS 1.3 session. */
static int accept_peer(int fd, const uint8_t *key, size_t key_size, struct wendy_conf_span cert,
                       struct wendy_conf_span roots, const char *tenant,
                       wendy_pki_connection **out, int64_t deadline, bool allow_device, bool lite,
                       const struct wendy_pki_stream *stream,
                       struct pki_tls_owned_identity *owned,const char *principal)
{
    if (out) *out = NULL;
    if (!out || !key || !key_size || (!cert.data && !(owned && owned->read_der)) || !tenant ||
        (stream && (!stream->read || !stream->write || !stream->wait))) {
        if (fd >= 0) close(fd);
        return -1;
    }
    wendy_pki_connection *c = pki_owned_calloc(1, sizeof *c);
    if (!c) { if (fd >= 0) close(fd); return -1; }
    c->allocation_scope=wendy_net_memory_scope_current();
    c->fd = fd;
    const char *stage="socket setup";int tls_error=0;
    if (owned) memcpy(c->mesh_tenant,tenant,37); /* Collect every verified path expiry. */
    if (stream) c->stream = *stream;
    else if (fd < 0 || fd >= FD_SETSIZE || fcntl(fd, F_SETFL, O_NONBLOCK) < 0) goto fail;
    if(owned && owned->preparation_owner){
        if(!wendy_pki_handshake_transfer(owned->preparation_owner,c))goto fail;
        owned->preparation_owner=NULL;
    }
    if(claim_legacy_handshake(c,deadline))goto fail;
    time_t verify_at=owned ? owned->verify_at : 0;
    stage="TLS configuration";
    if (configure(c, 1, key, key_size, cert, roots, owned, principal, verify_at,
                  owned!=NULL,owned && owned->read_der)) goto fail;
    /* Parsed DER anchors borrow the owned trust bundle through handshake. */
    int r;
    stage="TLS handshake";
    while (c->ssl.MBEDTLS_PRIVATE(state)!=MBEDTLS_SSL_HANDSHAKE_OVER) {
        r=handshake_step(c,owned!=NULL);
        if (r && wait_socket(c,r,deadline)) {tls_error=r;goto fail;}
    }
    if (stream && (wendy_pki_reset_in_progress() || esp_timer_get_time() >= deadline)) goto fail;
    stage="peer role and key metadata";
    if(finish_accept_peer(c,tenant,allow_device,lite,owned!=NULL))goto fail;
    wendy_pki_handshake_release(c);
    *out = c;
    return 0;
fail:
    ESP_LOGW("wendy_pki","TLS acceptance failed at %s: tls=%d state=%d flags=0x%x errno=%d",
        stage,tls_error,(int)c->ssl.MBEDTLS_PRIVATE(state),
        (unsigned)mbedtls_ssl_get_verify_result(&c->ssl),errno);
    wendy_pki_close(c);
    return -1;
}

int pki_tls_accept(int fd, const uint8_t *key, size_t key_size, struct wendy_conf_span cert,
                   struct wendy_conf_span roots, const char *tenant,
                   wendy_pki_connection **out, int64_t deadline)
{
    return accept_peer(fd, key, key_size, cert, roots, tenant, out, deadline, false, false, NULL,NULL,NULL);
}

int pki_tls_accept_stream(const struct wendy_pki_stream *stream,
                          const uint8_t *key, size_t key_size, struct wendy_conf_span cert,
                          struct wendy_conf_span roots, const char *tenant,
                          wendy_pki_connection **out, int64_t deadline)
{
    if (out) *out = NULL;
    if (!stream || wendy_pki_reset_in_progress() || esp_timer_get_time() >= deadline)
        return -1;
    return accept_peer(-1, key, key_size, cert, roots, tenant, out, deadline, false, false, stream,NULL,NULL);
}

int pki_tls_accept_lan(int fd, const uint8_t *key, size_t key_size, struct wendy_conf_span cert,
                       struct wendy_conf_span roots, const char *tenant,
                       wendy_pki_connection **out, int64_t deadline)
{
    return accept_peer(fd, key, key_size, cert, roots, tenant, out, deadline, true, false, NULL,NULL,NULL);
}

int pki_tls_accept_lite(int fd, const uint8_t *key, size_t key_size, struct wendy_conf_span cert,
                       struct wendy_conf_span roots, const char *tenant,
                       wendy_pki_connection **out, int64_t deadline)
{
    return accept_peer(fd, key, key_size, cert, roots, tenant, out, deadline, false, true, NULL,NULL,NULL);
}

static int accept_owned(int *fd,const struct wendy_pki_stream *stream,
    struct pki_tls_owned_identity *owned,
    struct wendy_conf_span roots,const char *tenant,const char *device,
    wendy_pki_connection **out,int64_t deadline)
{
    int result=-1;
    if (out) *out=NULL;
    if ((stream ? stream->read && stream->write && stream->wait : fd && *fd>=0) &&
        owned && owned->verify_at && tenant && device &&
        wendy_identity_uuid((const unsigned char*)tenant,strlen(tenant)) &&
        wendy_identity_uuid((const unsigned char*)device,strlen(device))) {
        char principal[106];
        /* The deployed ML-DSA operator Certificate message is 25979 bytes.
         * Reserve 26 KiB before receiving it instead of needing the old 24 KiB plus a new
         * 26 KiB contiguous replacement during the incoming handshake. */
        owned->input_reserve=26624;
        owned->reserve_records_first=true;
        snprintf(principal,sizeof principal,"spiffe://wendy.sh/tenant/%s/device/%s",tenant,device);
        int socket=-1;
        if(!stream){socket=*fd;*fd=-1;}
        result=accept_peer(socket,owned->key,owned->key_size,
            (struct wendy_conf_span){owned->certificate,owned->certificate_size},
            roots,tenant,out,deadline,!stream,false,stream,owned,principal);
    }
    if (fd && *fd>=0) {close(*fd);*fd=-1;}
    release_identity_input(owned);
    return result;
}
int pki_tls_accept_owned(int *fd,struct pki_tls_owned_identity *owned,
    struct wendy_conf_span roots,const char *tenant,const char *device,
    wendy_pki_connection **out,int64_t deadline)
{
    return accept_owned(fd,NULL,owned,roots,tenant,device,out,deadline);
}
int pki_tls_accept_owned_stream(const struct wendy_pki_stream *stream,
    struct pki_tls_owned_identity *owned,struct wendy_conf_span roots,
    const char *tenant,const char *device,wendy_pki_connection **out,int64_t deadline)
{
    return accept_owned(NULL,stream,owned,roots,tenant,device,out,deadline);
}

enum wendy_peer_role wendy_pki_get_peer_role(const wendy_pki_connection *connection)
{
    return connection ? connection->peer_role : WENDY_PEER_ROLE_NONE;
}

enum { READ_ALL_IDLE_TIMEOUT = -2 };
static int read_all(wendy_pki_connection *c, uint8_t *out, size_t n, int64_t deadline)
{
    size_t size = n;
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
            int waited = wait_socket(c, got, deadline);
            if (waited) {
                if (waited == SOCKET_WAIT_TIMEOUT && got == MBEDTLS_ERR_SSL_WANT_READ &&
                    n == size) return READ_ALL_IDLE_TIMEOUT;
                return -1;
            }
        }
    }
    return 0;
}

int wendy_pki_relay_upgrade(wendy_pki_connection *c, struct wendy_lite_trust *trust)
{
    memset(trust, 0, sizeof *trust);
    const char *stage = "grant key set";
    uint8_t header[4], count;
    int64_t deadline = esp_timer_get_time() + 10000000;
    if (read_all(c, header, 4, deadline) || memcmp(header, "WR\x03\x04", 4) ||
        read_all(c, &count, 1, deadline) || count < 1 || count > 2) goto fail;
    trust->count = count;
    for (unsigned i = 0; i < count; i++) {
        struct wendy_lite_key *key = &trust->keys[i];
        if (read_all(c, &key->id_size, 1, deadline) || key->id_size < 1 || key->id_size > 128 ||
            read_all(c, key->id, key->id_size, deadline) || wendy_lite_key_id(key->id, key->id_size) ||
            read_all(c, key->public_key, sizeof key->public_key, deadline)) goto fail;
        if (i && trust->keys[0].id_size == key->id_size &&
            !memcmp(trust->keys[0].id, key->id, key->id_size)) goto fail;
    }
    int64_t renew = esp_timer_get_time() + 240000000;
    bool first = true;
    for (;;) {
        stage = "heartbeat";
        deadline = esp_timer_get_time() + 30000000;
        if (deadline > renew) deadline = renew;
        int result = read_all(c, header, 4, deadline);
        if (result) {
            if (result == READ_ALL_IDLE_TIMEOUT && deadline == renew &&
                !wendy_pki_reset_in_progress()) {
                ESP_LOGI("wendy_pki", "refreshing broker control connection");
                return WENDY_PKI_RELAY_RENEW;
            }
            goto fail;
        }
        if (memcmp(header, "WR\x03", 3)) goto fail;
        if (header[3] == 1) {
            if (write_all(c, "WR\x03\x02", 4, deadline)) goto fail;
            if (first) ESP_LOGI("wendy_pki", "broker control heartbeat received and answered");
            first = false;
        } else if (header[3] == 3) {
            stage = "relay handoff";
            deadline = esp_timer_get_time() + 10000000;
            if (read_all(c, trust->session, 16, deadline) ||
                read_all(c, trust->grant_hash, 32, deadline)) goto fail;
            int fd = detach_socket(c);
            if (fd < 0) goto fail;
            ESP_LOGI("wendy_pki", "broker control handed off to operator TLS");
            return fd;
        } else goto fail;
    }
fail:
    ESP_LOGW("wendy_pki", "broker control failed at %s", stage);
    return WENDY_PKI_RELAY_FAILED;
}

int pki_relay_grant(wendy_pki_connection *c, const struct wendy_lite_trust *trust, int64_t deadline)
{
    if (!c || c->peer_role != WENDY_PEER_ROLE_OPERATOR) return -1;
    uint8_t *record = malloc(WENDY_LITE_GRANT_MAX);
    if (!record) return -1;
    int result = -1;
    if (read_all(c, record, 5, deadline) || memcmp(record, "WLG3", 4) ||
        record[4] < 1 || record[4] > 128) goto done;
    size_t size = WENDY_LITE_GRANT_FIXED + record[4];
    uint64_t expires = 0;
    if (read_all(c, record + 5, size - 5, deadline) ||
        wendy_lite_verify_grant(record, size, trust, c->device_hash, c->operator_hash, c->operator_spki_hash, time(NULL), &expires)) goto done;
    // presentBy authorizes presentation only. Bound the session separately by
    // its signed issue time and both authenticated certificates.
    if (c->device_expires <= 0 || c->operator_expires <= 0) goto done;
    if (expires > (uint64_t)c->device_expires) expires = (uint64_t)c->device_expires;
    if (expires > (uint64_t)c->operator_expires) expires = (uint64_t)c->operator_expires;
    int64_t remaining = (int64_t)expires - (int64_t)time(NULL);
    if (remaining <= 0 || remaining > 1800) goto done;
    c->relay_expires_us = esp_timer_get_time() + remaining * 1000000;
    if (write_all(c, "WLA2", 4, deadline)) goto done;
    result = 0;
done:
    if (result) ESP_LOGW("wendy_pki", "operator relay grant rejected");
    free(record);
    return result;
}

int pki_tls_agent_begin(const struct wendy_pki_stream *stream,const char *tenant,
    const char *device,struct pki_tls_owned_identity *owned,struct wendy_conf_span roots,
    wendy_pki_connection **out)
{
    if(out)*out=NULL;
    if(!out || !stream || !stream->read || !stream->write || !stream->wait ||
       !tenant || !device || !owned || owned->verify_at<=0 ||
       !wendy_identity_uuid((const unsigned char *)tenant,strlen(tenant)) ||
       !wendy_identity_uuid((const unsigned char *)device,strlen(device))){release_identity_input(owned);return -1;}
    wendy_pki_connection *c=pki_owned_calloc(1,sizeof *c);
    if(!c){release_identity_input(owned);return -1;}
    c->allocation_scope=wendy_net_memory_scope_current();c->fd=-1;c->stream=*stream;
    memcpy(c->mesh_tenant,tenant,37);memcpy(c->mesh_device,device,37);
    char principal[106];snprintf(principal,sizeof principal,"spiffe://wendy.sh/tenant/%s/device/%s",tenant,device);
    owned->input_reserve=26624;owned->reserve_records_first=true;
    int r=configure(c,1,owned->key,owned->key_size,
        (struct wendy_conf_span){owned->certificate,owned->certificate_size},roots,
        owned,principal,owned->verify_at,true,owned->read_der!=NULL);
    /* Native WendyCom is not an app/carrier ALPN and can accept a device or
     * operator. Do not use finish_mesh or reinterpret its peer as a UUID. */
    release_identity_input(owned);
    if(r){wendy_pki_close(c);return -1;}
    *out=c;return 0;
}
int pki_tls_agent_advance(wendy_pki_connection *c)
{
    if(!c)return -1;
    wendy_net_memory_scope_t previous=connection_scope(c);
    int result=1;
    if(c->ssl.MBEDTLS_PRIVATE(state)!=MBEDTLS_SSL_HANDSHAKE_OVER){
        int r=handshake_step(c,true);
        if(r==MBEDTLS_ERR_SSL_WANT_READ){result=-2;goto done;}
        if(r==MBEDTLS_ERR_SSL_WANT_WRITE){result=-3;goto done;}
        if(r){
            result=-1;goto done;
        }
    }
    if(c->ssl.MBEDTLS_PRIVATE(state)==MBEDTLS_SSL_HANDSHAKE_OVER){
        result=finish_accept_peer(c,c->mesh_tenant,true,false,true);
    }
done:
    wendy_net_memory_scope_leave(previous);return result;
}

int pki_tls_net_begin(const struct wendy_pki_stream *stream,bool server,
    const char *tenant,const char *device,struct pki_tls_owned_identity *owned,
    struct wendy_conf_span roots,bool application,wendy_pki_connection **out)
{
    *out=NULL;
    if(!owned || owned->verify_at<=0){release_identity_input(owned);return -1;}
    wendy_pki_connection *c=pki_owned_calloc(1,sizeof *c);
    if(!c){release_identity_input(owned);return -1;}
    c->allocation_scope=wendy_net_memory_scope_current();
    c->fd=-1;c->stream=*stream;
    char principal[106];
    snprintf(principal,sizeof principal,"spiffe://wendy.sh/tenant/%s/device/%s",tenant,device);
    bool streamed=owned && owned->read_der;
    int result=configure(c,server,owned->key,owned->key_size,
        (struct wendy_conf_span){owned->certificate,owned->certificate_size},roots,
        owned,principal,owned->verify_at,application,streamed);
    static const char *const carrier_alpn[]={"wendy-local-mesh-ble/2",NULL};
    static const char *const app_alpn[]={"wendy-app-mesh-tls/1",NULL};
    if(!result)result=configure_mesh_alpn(c,application ? app_alpn:carrier_alpn);
    if(!result)result=mbedtls_ssl_set_hostname(&c->ssl,NULL);
    if(!result){memcpy(c->mesh_tenant,tenant,37);memcpy(c->mesh_device,device,37);*out=c;}
    else wendy_pki_close(c);
    release_identity_input(owned);
    return result ? -1:0;
}
static int net_advance(wendy_pki_connection *c,bool application,const char *peer)
{
    if(c->ssl.MBEDTLS_PRIVATE(state)!=MBEDTLS_SSL_HANDSHAKE_OVER){
        int r=handshake_step(c,application);
        if(r==MBEDTLS_ERR_SSL_WANT_READ)return -2;
        if(r==MBEDTLS_ERR_SSL_WANT_WRITE)return -3;
        if(r)return -1;
        if(c->ssl.MBEDTLS_PRIVATE(state)!=MBEDTLS_SSL_HANDSHAKE_OVER)return 1;
    }
    release_presented_chain(c);
    if(mbedtls_ssl_get_verify_result(&c->ssl))return -1;
    return finish_mesh(c,c->mesh_tenant,c->mesh_device,peer,false,
        application ? "wendy-app-mesh-tls/1":"wendy-local-mesh-ble/2",c->device_expires,
        (struct wendy_conf_span){0},!application);
}

int pki_tls_net_advance(wendy_pki_connection *c,bool application,const char *peer)
{
    wendy_net_memory_scope_t previous=connection_scope(c);
    int result=net_advance(c,application,peer);
    wendy_net_memory_scope_leave(previous);return result;
}

int pki_tls_net_connect(const char* host, unsigned port, const char* tenant, const char* device,
    const char* peer, struct pki_tls_owned_identity* owned,
    struct wendy_conf_span roots, const char* protocol, wendy_pki_connection** out)
{
    if (out) *out = NULL;
    int result = -1;
    if (owned && owned->key && (owned->certificate || owned->read_der) && protocol &&
        (!strcmp(protocol,"wendy-local-mesh-ble/2") ||
         !strcmp(protocol,"wendy-app-mesh-tls/1")))
        result = open_tls(host, port, owned->key, owned->key_size, (struct wendy_conf_span){owned->certificate,owned->certificate_size}, roots, out,
            tenant, device, peer, NULL, false, false, NULL, NULL, protocol, owned, NULL);
    release_identity_input(owned);
    return result;
}

int pki_tls_net_accept(int *fd,const char *tenant,const char *device,
    struct pki_tls_owned_identity *owned,struct wendy_conf_span roots,
    const char *protocol,wendy_pki_connection **out)
{
    if (out) *out=NULL;
    int result=-1;
    if (fd && *fd>=0 && owned && owned->key && (owned->certificate || owned->read_der) && protocol &&
        (!strcmp(protocol,"wendy-local-mesh-ble/2") ||
         !strcmp(protocol,"wendy-app-mesh-tls/1")))
        result=open_tls(NULL,0,owned->key,owned->key_size,(struct wendy_conf_span){owned->certificate,owned->certificate_size},roots,out,
            tenant,device,NULL,NULL,true,false,NULL,NULL,protocol,owned,fd);
    if (fd && *fd>=0) {close(*fd);*fd=-1;}
    release_identity_input(owned);
    return result;
}

int pki_tls_net_stream(const struct wendy_pki_stream *stream,bool server,const char *tenant,
    const char *device,const char *expected_peer,struct pki_tls_owned_identity *owned,
    struct wendy_conf_span roots,wendy_pki_connection **out)
{
    if(out)*out=NULL;
    int result=-1;
    if(stream && owned && owned->key && (owned->certificate || owned->read_der))
        result=open_tls(NULL,0,owned->key,owned->key_size,(struct wendy_conf_span){owned->certificate,owned->certificate_size},roots,out,
            tenant,device,expected_peer,stream,server,false,NULL,NULL,"wendy-local-mesh-ble/2",owned,NULL);
    release_identity_input(owned);
    return result;
}
