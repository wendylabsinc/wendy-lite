/* Host adapter for the production TLS implementation. Go drives real TLS peers. */
#include "wendy_pki_internal.h"
#include "wendy_pki_crypto.h"
#include "wendy_pki_native_prepare.h"
#include "wendy_cert_bundle.h"
#include "wendy_pki_verify.h"
#include "wendy_pki_parsed_identity.h"
#include "wendy_pki_certificate_policy.h"
#include "esp_timer.h"
#include <mbedtls/net_sockets.h>
#include <mbedtls/platform.h>
#include <assert.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
static int64_t clock_advance;
int64_t esp_timer_get_time(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000000 + t.tv_nsec / 1000 + clock_advance;
}
static unsigned char *load(const char *path, size_t *size) {
    FILE *f = fopen(path, "rb"); assert(f); fseek(f, 0, SEEK_END);
    *size = ftell(f); rewind(f); unsigned char *p = calloc(1, *size + 1);
    assert(p && fread(p, 1, *size, f) == *size); fclose(f); return p;
}
static bool resetting;
bool wendy_pki_reset_in_progress(void) { return resetting; }
struct der_source_test {mbedtls_x509_crt chain;unsigned reads;bool corrupt,exhausted;uint8_t *trust;size_t trust_size;struct wendy_pki_mesh_public_index index;};
static void certificate_key_views(const mbedtls_x509_crt *chain)
{
    for(const mbedtls_x509_crt *part=chain;part && part->raw.len;part=part->next){
        const mbedtls_pk_context *pk=&part->pk;
        if(!pk->MBEDTLS_PRIVATE(pqc_raw))continue;
        const uint8_t *key=pk->MBEDTLS_PRIVATE(pqc_raw);
        size_t length=pk->MBEDTLS_PRIVATE(pub_raw_len);
        assert(pk->MBEDTLS_PRIVATE(pqc_raw_borrowed));
        assert(key>=part->raw.p && key<=part->raw.p+part->raw.len);
        assert(length<=(size_t)(part->raw.p+part->raw.len-key));
        /* Standalone SPKI parsing still owns its key after input is freed. */
        size_t n=part->pk_raw.len;assert(n>0);
        uint8_t *input=malloc(n);assert(input);
        memcpy(input,part->pk_raw.p,n);
        mbedtls_pk_context copy;mbedtls_pk_init(&copy);
        assert(!mbedtls_pk_parse_public_key(&copy,input,n));free(input);
        assert(!copy.MBEDTLS_PRIVATE(pqc_raw_borrowed));
        assert(copy.MBEDTLS_PRIVATE(pub_raw_len)==length);
        assert(!memcmp(copy.MBEDTLS_PRIVATE(pqc_raw),key,length));
        mbedtls_pk_free(&copy);
    }
}
static int read_der_test(void *context,unsigned index,uint8_t **bytes,size_t *size)
{
    struct der_source_test *source=context;source->reads++;
    const mbedtls_x509_crt *part=&source->chain;
    for(unsigned i=0;i<index && part;i++)part=part->next;
    *bytes=NULL;*size=0;if(!part || !part->raw.len){source->exhausted=true;return 0;}
    const char *replacement=getenv("WENDY_TLS_LATE_DER_PATH");
    if(source->exhausted && index==1 && replacement) {
        *bytes=load(replacement,size);assert(*size==part->raw.len);
        assert(memcmp(*bytes,part->raw.p,*size));return 1;
    }
    *bytes=pki_owned_malloc(part->raw.len);if(!*bytes)return -1;
    *size=part->raw.len;memcpy(*bytes,part->raw.p,*size);
    if(source->corrupt && index==1)(*bytes)[*size-1]^=1;
    return 1;
}
static int hash_der_test(void *context,unsigned index,uint8_t hash[32],size_t *size)
{
    struct der_source_test *source=context;
    const mbedtls_x509_crt *part=&source->chain;
    for(unsigned i=0;i<index && part;i++)part=part->next;
    *size=0;
    if(!part || !part->raw.len)return 0;
    if(wendy_pki_sha256(part->raw.p,part->raw.len,hash))return -1;
    *size=part->raw.len;return 1;
}
static int read_der_range_test(void *context,unsigned index,size_t offset,
    uint8_t *output,size_t count,const uint8_t expected[32])
{
    uint8_t *der=NULL,hash[32];size_t size=0;
    int loaded=read_der_test(context,index,&der,&size);
    bool valid=loaded==1 && offset<=size && count<=size-offset &&
        !wendy_pki_sha256(der,size,hash) && !memcmp(hash,expected,32);
    if(valid && count)memcpy(output,der+offset,count);
    pki_owned_free(der);return valid ? (int)count:-1;
}

static void public_source_destroy(void *context)
{
    struct der_source_test *source=context;
    mbedtls_x509_crt_free(&source->chain);free(source->trust);free(source);
}
static int public_trust_test(void *context,uint8_t **bytes,size_t *size)
{
    struct der_source_test *source=context;
    *size=source->trust_size;*bytes=malloc(*size+1);assert(*bytes);
    memcpy(*bytes,source->trust,*size+1);return 0;
}
static int public_metadata_test(void *context,struct wendy_pki_mesh_public_index *out)
{*out=((struct der_source_test *)context)->index;return 0;}
static void public_index_snapshot_test(wendy_pki_connection *c)
{
    if(!c->public_chain)return;
    struct der_source_test *source=c->public_chain->context;
    struct wendy_pki_mesh_identity clock={.config_generation=17};
    memcpy(clock.tenant,c->mesh_tenant,sizeof clock.tenant);
    memcpy(clock.device,c->mesh_device,sizeof clock.device);
    unsigned reads=source->reads;
    struct wendy_pki_mesh_public_index index;
    assert(!wendy_pki_mesh_public_index_snapshot(c,&clock,&index));
    assert(index.count==c->public_chain->count && index.config_generation==17);
    unsigned i=0;
    for(const mbedtls_x509_crt *part=&source->chain;part && part->raw.len;part=part->next,i++){
        assert(i<index.count && index.sizes[i]==part->raw.len);
        assert(!memcmp(index.hashes[i],c->public_chain->hashes[i],32));
    }
    assert(i==index.count && source->reads==reads);
}
static struct pki_public_chain *public_source_test(const mbedtls_x509_crt *input,const uint8_t *trust,size_t trust_size)
{
    struct pki_public_chain *public=calloc(1,sizeof *public);
    struct der_source_test *source=calloc(1,sizeof *source);assert(public && source);
    mbedtls_x509_crt_init(&source->chain);
    for(const mbedtls_x509_crt *part=input;part && part->raw.len;part=part->next) {
        assert(public->count<8);
        assert(!mbedtls_x509_crt_parse_der(&source->chain,part->raw.p,part->raw.len));
        assert(!wendy_pki_sha256(part->raw.p,part->raw.len,public->hashes[public->count++]));
    }
    certificate_key_views(&source->chain);
    source->index.count=public->count;source->index.config_generation=17;
    source->index.certificate_epoch=1;
    memcpy(source->index.hashes,public->hashes,sizeof source->index.hashes);
    public->sizes=source->index.sizes;public->metadata=public_metadata_test;
    public->context=source;public->read=read_der_test;public->destroy=public_source_destroy;
    if(getenv("WENDY_TLS_RELOAD_TRUST")) {
        source->trust=malloc(trust_size+1);assert(source->trust);
        memcpy(source->trust,trust,trust_size);source->trust[trust_size]=0;source->trust_size=trust_size;
        public->load_trust=public_trust_test;
    }
    if(getenv("WENDY_TLS_PUBLIC_CORRUPT"))public->hashes[0][0]^=1;
    return public;
}
static bool short_writes;
static bool truncate_certificate, certificate_record;
static size_t record_remaining;
static unsigned send_calls, partial_sends, blocked_sends;
/* The production TLS source is compiled with send renamed to this adapter.
 * Alternate short writes with EAGAIN so each handshake flight must resume. */
ssize_t wendy_test_send(int fd, const void *buffer, size_t size, int flags) {
    if (short_writes) {
        if (truncate_certificate && certificate_record && !record_remaining) {
            /* End the transport after one intact encrypted Certificate record,
             * before the remainder of the handshake message can be sent. */
            assert(!shutdown(fd, SHUT_WR));
            errno = ECONNRESET;
            return -1;
        }
        if (!record_remaining) {
            const unsigned char *record = buffer;
            assert(size >= 5 && size == 5 + ((size_t)record[3] << 8) + record[4]);
            record_remaining = size;
            if (truncate_certificate && record[0] == MBEDTLS_SSL_MSG_APPLICATION_DATA)
                certificate_record = true;
        }
        if (++send_calls % 2 == 0) {
            blocked_sends++;
            errno = blocked_sends%3==0 ? ENOBUFS : blocked_sends%3==1 ? EAGAIN : ENOMEM;
            return -1;
        }
        if (size > 512) {
            size = 512;
            partial_sends++;
        }
    }
    ssize_t n = send(fd, buffer, size, flags);
    if (short_writes && n > 0) {
        assert((size_t)n <= record_remaining);
        record_remaining -= (size_t)n;
    }
    return n;
}
static void wait_io(wendy_pki_connection *c, int result) {
    assert(result == -2 || result == -3);
    assert(wendy_pki_wait(c,result == -3,esp_timer_get_time()+3000000) >= 0);
}
/* Ordinary duplex echo over the existing short-I/O transport. Keep receiving
 * while a previous output record is backpressured, as the native TCP relay
 * does. Separate buffers preserve the SSL write retry's original bytes. */
static void duplex_bulk_echo(wendy_pki_connection *c) {
    unsigned char input[1024],output[1024];
    size_t chunk=sizeof input;
    const char *configured=getenv("WENDY_TLS_DUPLEX_CHUNK");
    if(configured){chunk=(size_t)strtoul(configured,NULL,10);assert(chunk && chunk<=sizeof input);}
    size_t have=0,pending=0,offset=0,received=0,sent=0;
    int64_t deadline=esp_timer_get_time()+INT64_C(10000000);
    while(sent<65536 && esp_timer_get_time()<deadline){
        bool progress=false;
        if(!have && received<65536){
            int n=wendy_pki_read(c,input,chunk);
            if(n>0){have=n;received+=n;progress=true;}
            else assert(n==-2 || n==-3);
        }
        if(!pending && have){
            memcpy(output,input,have);pending=have;have=0;offset=0;
        }
        if(pending){
            int n=wendy_pki_write(c,output+offset,pending-offset);
            if(n>0){offset+=n;sent+=n;progress=true;if(offset==pending)pending=0;}
            else assert(n==-2 || n==-3);
        }
        if(!progress)assert(wendy_pki_wait(c,pending!=0,deadline)>=0);
    }
    assert(received==65536 && sent==65536);
}
static void bulk_echo_and_expiry(wendy_pki_connection *c) {
    const mbedtls_x509_crt *retained=mbedtls_ssl_get_peer_cert(&c->ssl);
    uint8_t retained_hash[32];
    if (c->config.MBEDTLS_PRIVATE(wendy_compact_peer_chain) && retained) {
        assert(!retained->next && retained->MBEDTLS_PRIVATE(own_buffer));
        assert(!wendy_pki_sha256(retained->raw.p,retained->raw.len,retained_hash));
    }
    unsigned char bytes[257];size_t received=0;
    if(getenv("WENDY_TLS_NORMAL_DUPLEX")){
        duplex_bulk_echo(c);received=65536;
    }
    while(received<65536) {
        size_t count=sizeof bytes;if(count>65536-received) count=65536-received;
        int n=wendy_pki_read(c,bytes,count);
        if(n<0) {wait_io(c,n);continue;}
        assert(n>0);received+=n;
        size_t sent=0;
        while(sent<(size_t)n) {
            int written=wendy_pki_write(c,bytes+sent,(size_t)n-sent);
            if(written>0)sent+=written;else wait_io(c,written);
        }
    }
#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
    assert(c->compact_records && c->ssl.MBEDTLS_PRIVATE(in_buf_len)==2048);
    assert(mbedtls_ssl_get_max_in_record_payload(&c->ssl)==16384);
#endif
    if (c->config.MBEDTLS_PRIVATE(wendy_compact_peer_chain) && retained) {
        uint8_t after[32];
        /* Many input-buffer overwrites/resizes must not invalidate the owned
         * leaf needed for routing identity/SPKI checks after authentication. */
        assert(!wendy_pki_sha256(retained->raw.p,retained->raw.len,after));
        assert(!memcmp(after,retained_hash,sizeof after));
        struct wendy_pki_mesh_peer authenticated;
        assert(!wendy_pki_mesh_authenticated_peer(c,&authenticated));
    }
    assert(c->session_deadline_us>esp_timer_get_time());
    if(!getenv("WENDY_TLS_NORMAL_ONLY")){
        clock_advance=c->session_deadline_us-esp_timer_get_time()+1;
        assert(wendy_pki_read(c,bytes,1)==-1);
        assert(wendy_pki_write(c,bytes,1)==-1);
        assert(!wendy_pki_pending(c));
        assert(wendy_pki_wait(c,false,INT64_MAX)==-1);
    }
}
static void outbound(unsigned port, const unsigned char *key, size_t kn,
                     const unsigned char *cert,size_t cn,const unsigned char *root,size_t rn,
                     bool truncate) {
    short_writes = true;
    truncate_certificate = truncate;
    wendy_pki_connection *c = NULL;
    int connected = pki_tls_connect("localhost", port, key, kn, (struct wendy_conf_span){cert,cn},
        (struct wendy_conf_span){root, rn}, &c);
    if (truncate) {
        assert(connected && !c && certificate_record && !record_remaining);
        assert(partial_sends && blocked_sends);
        return;
    }
    assert(!connected);
    assert(c && partial_sends && blocked_sends);
#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
    /* Mixed CA chains still authenticate, but their temporary reassembly
     * headroom must not remain attached to a live application connection. */
    assert(c->ssl.MBEDTLS_PRIVATE(in_buf_len) >= 16384);
    assert(c->ssl.MBEDTLS_PRIVATE(in_buf_len) < 20000);
    assert(mbedtls_ssl_get_max_in_record_payload(&c->ssl) == 16384);
    /* TLS 1.3 reserves one byte for its inner content type. */
    assert(mbedtls_ssl_get_max_out_record_payload(&c->ssl) == MBEDTLS_SSL_OUT_CONTENT_LEN - 1);
#endif
    size_t written = 0, received = 0;
    char response[5];
    while (written < 5) {
        int n = wendy_pki_write(c, &"hello"[written], 5 - written);
        if (n > 0) written += (size_t)n;
        else wait_io(c, n);
    }
    while (received < sizeof response) {
        int n = wendy_pki_read(c, response + received, sizeof response - received);
        if (n > 0) received += (size_t)n;
        else wait_io(c, n);
    }
    assert(!memcmp(response, "world", sizeof response));
    wendy_pki_close(c);
}

/* A second Mbed TLS endpoint negotiates 512-byte TLS records so the production
 * server receives a valid Certificate across records, within its fixed bound. */
static void fragmented_client(const char *port, const unsigned char *key_der, size_t kn,
                              const unsigned char *cert_pem, size_t cn,
                              const unsigned char *roots_pem, size_t rn) {
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config config;
    mbedtls_x509_crt cert, roots;
    mbedtls_pk_context key;
    mbedtls_net_context net;
    mbedtls_ssl_init(&ssl); mbedtls_ssl_config_init(&config);
    mbedtls_x509_crt_init(&cert); mbedtls_x509_crt_init(&roots);
    mbedtls_pk_init(&key); mbedtls_net_init(&net);
    assert(!wendy_pki_crypto_init());
    assert(!pki_parse_certificate_bundle(&cert,cert_pem,cn,false));
    assert(!pki_parse_certificate_bundle(&roots,roots_pem,rn,false));
    assert(!mbedtls_pk_parse_key(&key, key_der, kn, NULL, 0));
    assert(!mbedtls_ssl_config_defaults(&config, MBEDTLS_SSL_IS_CLIENT,
        MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT));
    mbedtls_ssl_conf_authmode(&config, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&config, &roots, NULL);
    mbedtls_ssl_conf_cert_profile(&config, wendy_pki_certificate_profile());
    mbedtls_ssl_conf_min_tls_version(&config, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_max_tls_version(&config, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_tls13_key_exchange_modes(&config,
        MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL);
    assert(!mbedtls_ssl_conf_max_frag_len(&config, MBEDTLS_SSL_MAX_FRAG_LEN_512));
    assert(!mbedtls_ssl_conf_own_cert(&config, &cert, &key));
    assert(!mbedtls_ssl_setup(&ssl, &config));
#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
    assert(ssl.MBEDTLS_PRIVATE(in_buf_len) < 20000);
#endif
    assert(!mbedtls_ssl_set_hostname(&ssl, "localhost"));
    assert(!mbedtls_net_connect(&net, "127.0.0.1", port, MBEDTLS_NET_PROTO_TCP));
    struct timeval timeout = {.tv_sec = 3};
    assert(!setsockopt(net.fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout));
    assert(!setsockopt(net.fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout));
    mbedtls_ssl_set_bio(&ssl, &net, mbedtls_net_send, mbedtls_net_recv, NULL);
    assert(!mbedtls_ssl_handshake(&ssl));
    assert(!mbedtls_ssl_get_verify_result(&ssl));
    assert(mbedtls_ssl_get_max_out_record_payload(&ssl) <= 512);
    assert(cert.raw.len > 512);
    assert(mbedtls_ssl_write(&ssl, (const unsigned char *)"hello", 5) == 5);
    unsigned char response[5];
    size_t received = 0;
    while (received < sizeof response) {
        int n = mbedtls_ssl_read(&ssl, response + received, sizeof response - received);
        assert(n > 0); received += (size_t)n;
    }
    assert(!memcmp(response, "world", sizeof response));
    mbedtls_ssl_free(&ssl); mbedtls_ssl_config_free(&config);
    mbedtls_x509_crt_free(&cert); mbedtls_x509_crt_free(&roots);
    mbedtls_pk_free(&key); mbedtls_net_free(&net);
}

/* BLE supplies a byte stream rather than a socket. Keep the backing socket
 * outside the TLS connection and force fragmented reads, writes and retries. */
struct test_stream {
    int fd;
    unsigned reads, writes, partial_reads, partial_writes;
    unsigned blocked_reads, blocked_writes, read_waits, write_waits;
    unsigned opposite_reads, opposite_writes, injected_wait;
    bool fail_wait;
};
#include "tls_agent_bio.h"
static ssize_t stream_read(void *context, void *buffer, size_t size) {
    struct test_stream *s = context;
    if (++s->reads == 1) {
        s->opposite_reads++;
        s->injected_wait = 2;
        return -3;
    }
    if (s->reads % 3 == 1) {
        s->blocked_reads++;
        return -2;
    }
    if (size > 73) { size = 73; s->partial_reads++; }
    ssize_t n = recv(s->fd, buffer, size, 0);
    return n < 0 && (errno == EAGAIN || errno == EINTR) ? -2 : n;
}
static ssize_t stream_write(void *context, const void *buffer, size_t size) {
    struct test_stream *s = context;
    if (++s->writes == 1) {
        s->opposite_writes++;
        s->injected_wait = 1;
        return -2;
    }
    if (s->writes % 3 == 1) {
        s->blocked_writes++;
        return -3;
    }
    if (size > 61) { size = 61; s->partial_writes++; }
    ssize_t n = send(s->fd, buffer, size, 0);
    return n < 0 && (errno == EAGAIN || errno == EINTR) ? -3 : n;
}
static int stream_wait(void *context, bool writing, int64_t deadline) {
    struct test_stream *s = context;
    if (writing) s->write_waits++; else s->read_waits++;
    if (s->fail_wait) return -1;
    if (s->injected_wait) {
        assert(writing == (s->injected_wait == 2));
        s->injected_wait = 0;
        return 0;
    }
    int64_t remaining = deadline - esp_timer_get_time();
    if (remaining <= 0) return -1;
    struct pollfd fd = {.fd = s->fd, .events = writing ? POLLOUT : POLLIN};
    return poll(&fd, 1, (int)((remaining + 999) / 1000)) == 1 ? 0 : -1;
}
/* Ordinary physical BLE starts on the existing I/O slot. The crypto queue
 * remains separately available for TLS steps and native admission is outside it. */
struct physical_ble_io_fixture {
    const struct wendy_pki_stream *stream;
    struct pki_tls_owned_identity *owned;
    struct wendy_conf_span roots;
    wendy_pki_connection **connection;
    int result;
};
static void physical_ble_io_accept(void *argument)
{
    struct physical_ble_io_fixture *f=argument;
    assert(!wendy_pki_work_is_current());
    uint8_t cookie=0;
    assert(pki_native_prepare_claim(&cookie,esp_timer_get_time()+5000000));
    f->owned->preparation_owner=&cookie;
    f->result=pki_tls_accept_owned_stream(f->stream,f->owned,f->roots,
        "2558fd76-afc7-466e-9613-6b715296a526","00000000-0000-4000-8000-000000000004",
        f->connection,esp_timer_get_time()+5000000);
    assert(!wendy_pki_handshake_busy());
    wendy_pki_handshake_release(&cookie);
}
static void stream_exchange(wendy_pki_connection *c, struct test_stream *s) {
    assert(wendy_pki_fd(c) == -1);
    /* A stream cannot be handed off as a TCP fd, and failure must retain it. */
    assert(wendy_pki_detach(c) == -1);
    char hello[5];
    size_t received = 0, written = 0;
    while (received < sizeof hello) {
        size_t size = received ? sizeof hello - received : 1;
        ssize_t n = wendy_pki_read(c, hello + received, size);
        if (n > 0) {
            received += (size_t)n;
            /* One-byte application reads must leave decrypted data visible
             * even when no additional transport packet arrives. */
            if (received == 1) assert(wendy_pki_pending(c));
        } else {
            assert(n == -2 || n == -3);
            assert(!stream_wait(s, n == -3, esp_timer_get_time() + 3000000));
        }
    }
    assert(!memcmp(hello, "hello", sizeof hello));
    assert(!wendy_pki_pending(c));
    while (written < 5) {
        ssize_t n = wendy_pki_write(c, &"world"[written], 5 - written);
        if (n > 0) written += (size_t)n;
        else {
            assert(n == -2 || n == -3);
            assert(!stream_wait(s, n == -3, esp_timer_get_time() + 3000000));
        }
    }
    assert(s->partial_reads && s->partial_writes &&
           s->blocked_reads && s->blocked_writes && s->read_waits && s->write_waits);
    assert(s->opposite_reads && s->opposite_writes && !s->injected_wait);
    resetting = true;
    assert(wendy_pki_read(c, hello, 1) == -1);
    assert(wendy_pki_write(c, "x", 1) == -1);
    resetting = false;
    wendy_pki_close(c);
    /* The BLE/L2CAP owner still owns its stream after TLS teardown. */
    assert(fcntl(s->fd, F_GETFD) >= 0);
    close(s->fd);
}

/* Receive capacity is independent of our smaller transmit limit unless
 * a real max_fragment_length extension was negotiated. */
static void asymmetric_record_limits(void) {
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config config;
    mbedtls_ssl_session session;
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&config);
    assert(mbedtls_ssl_setup_with_input_reserve(&ssl,&config,SIZE_MAX)==MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
    assert(!ssl.MBEDTLS_PRIVATE(conf));
    mbedtls_ssl_session_init(&session);
    ssl.MBEDTLS_PRIVATE(conf) = &config;
    ssl.MBEDTLS_PRIVATE(session_out) = &session;
    assert(mbedtls_ssl_get_max_in_record_payload(&ssl) == 16384);
    assert(mbedtls_ssl_get_max_out_record_payload(&ssl) == MBEDTLS_SSL_OUT_CONTENT_LEN);
    session.MBEDTLS_PRIVATE(mfl_code) = MBEDTLS_SSL_MAX_FRAG_LEN_1024;
    assert(mbedtls_ssl_get_max_in_record_payload(&ssl) == 1024);
    ssl.MBEDTLS_PRIVATE(session_out) = NULL;
    ssl.MBEDTLS_PRIVATE(session_negotiate) = &session;
    session.MBEDTLS_PRIVATE(mfl_code) = MBEDTLS_SSL_MAX_FRAG_LEN_512;
    assert(mbedtls_ssl_get_max_in_record_payload(&ssl) == 512);
    session.MBEDTLS_PRIVATE(mfl_code) = MBEDTLS_SSL_MAX_FRAG_LEN_NONE;
    assert(mbedtls_ssl_get_max_in_record_payload(&ssl) == 16384);
    /* Stack-owned test structures; detach before freeing the SSL context. */
    ssl.MBEDTLS_PRIVATE(session_negotiate) = NULL;
    ssl.MBEDTLS_PRIVATE(conf) = NULL;
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_session_free(&session);
    mbedtls_ssl_config_free(&config);
}
static int tls_test_once(int argc, char **argv) {
    char byte;
    assert(signal(SIGPIPE,SIG_IGN)!=SIG_ERR);
    if(!getenv("WENDY_TLS_NORMAL_ONLY")){
        asymmetric_record_limits();
        struct pki_tls_owned_identity rejected = {.key=calloc(1,1),.key_size=1,.certificate=calloc(1,1),.trust=calloc(1,1)};
        assert(rejected.key && rejected.certificate);
        wendy_pki_connection *rejected_connection = (void*)1;
        assert(pki_tls_net_connect(NULL,0,NULL,NULL,NULL,&rejected,(struct wendy_conf_span){0},
            "invalid",&rejected_connection));
        assert(!rejected.key && !rejected.certificate && !rejected.key_size && !rejected_connection);

        /* Rejected peers can close before TLS sends its alert. Match lwIP's
         * error-return behavior instead of terminating the host adapter. */
        assert(signal(SIGPIPE, SIG_IGN) != SIG_ERR);
        /* Reset revokes existing sessions before the client requests reboot. */
        wendy_pki_connection old = {0};
        resetting = true;
        assert(wendy_pki_read(&old, &byte, 1) == -1);
        assert(wendy_pki_write(&old, "x", 1) == -1);
        resetting = false;
    }
    assert(argc == 5 || argc == 6 || argc == 7 || argc == 8); size_t kn, cn, rn;
    unsigned char *key = load(argv[1], &kn), *cert = load(argv[2], &cn), *root = load(argv[3], &rn);
    size_t root_der_size=0;
    assert(!wendy_cert_bundle_measure(root,rn,&root_der_size));
    uint8_t *root_der=calloc(1,root_der_size+1);assert(root_der);
    assert(!wendy_cert_bundle_import(root,rn,root_der,root_der_size,&root_der_size));
    free(root);root=root_der;rn=root_der_size;
    size_t cert_der_size=0;
    assert(!wendy_cert_bundle_measure(cert,cn,&cert_der_size));
    uint8_t *cert_der=calloc(1,cert_der_size+1);assert(cert_der);
    assert(!wendy_cert_bundle_import(cert,cn,cert_der,cert_der_size,&cert_der_size));
    free(cert);cert=cert_der;cn=cert_der_size;
    assert(!pki_identity_encoding(cert,cn,key,kn));
    if(!getenv("WENDY_TLS_NORMAL_ONLY")){
        unsigned char *invalid = malloc(cn+1); assert(invalid);
        memcpy(invalid,cert,cn); invalid[cn]='x';
        assert(pki_identity_encoding(invalid,cn+1,key,kn));
        invalid[cn/2]=0;
        assert(pki_identity_encoding(invalid,cn,key,kn)); free(invalid);
        invalid=malloc(kn+1); assert(invalid); memcpy(invalid,key,kn); invalid[kn]=0;
        assert(pki_identity_encoding(cert,cn,invalid,kn+1)); free(invalid);
    }

    if(argc==8 && !strcmp(argv[4],"https-stream")){
        int fd=socket(AF_INET,SOCK_STREAM,0);assert(fd>=0);
        struct sockaddr_in address={.sin_family=AF_INET,.sin_port=htons((uint16_t)atoi(argv[6]))};
        address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        assert(!connect(fd,(struct sockaddr *)&address,sizeof address));
        assert(!fcntl(fd,F_SETFL,O_NONBLOCK));
        struct test_stream transport={.fd=fd};
        struct wendy_pki_stream stream={.context=&transport,.read=stream_read,.write=stream_write,.wait=stream_wait};
        uint8_t *reply=NULL;size_t size=0,expected_size=0;
        unsigned char *expected=load(argv[7],&expected_size);
        assert(!pki_http_post_stream(argv[5],"application/timestamp-query","nonce",5,
            (struct wendy_conf_span){root,rn},&stream,&reply,&size));
        assert(size==expected_size && !memcmp(reply,expected,size));
        assert(fcntl(fd,F_GETFD)>=0);close(fd);
        free(reply);free(expected);free(key);free(cert);free(root);
        puts("normal HTTPS over caller-owned byte relay passes");return 0;
    }

    if (argc == 7) {
        assert(!strncmp(argv[4], "http-", 5));
        bool renew = !strcmp(argv[4], "http-renew");
        uint8_t *body = NULL;
        size_t body_size = 0;
        char *authority = NULL;
        int result = pki_http_post_enrollment(argv[5], "application/json", renew ? NULL : "test-token",
            "{}", 2, renew ? key : NULL, renew ? kn : 0, (struct wendy_conf_span){renew ? cert : NULL,renew ? cn : 0},
            (struct wendy_conf_span){root, rn}, &body, &body_size, &authority);
        if (!strcmp(argv[4], "http-reject")) {
            assert(result && !body && !authority);
        } else {
            assert(!result);
            if (!strcmp(argv[4], "http-large")) {
                assert(body_size == 40000 && body[body_size] == 0);
                for (size_t i = 0; i < body_size; i++) assert(body[i] == 'x');
            } else assert(body_size == 2 && !memcmp(body, "{}", 2));
            if (!strcmp(argv[6], "-")) assert(!authority);
            else {
                size_t expected_size;
                unsigned char *expected = load(argv[6], &expected_size);
                assert(authority && strlen(authority) == expected_size &&
                       !memcmp(authority, expected, expected_size));
                free(expected);
            }
        }
        free(authority); free(body); free(key); free(cert); free(root);
        return 0;
    }
    if (argc == 6) {
        if (!strcmp(argv[4], "fragment-client")) {
            fragmented_client(argv[5], key, kn, cert, cn, root, rn);
            free(key); free(cert); free(root);
            return 0;
        }
        bool router_protocol=getenv("WENDY_TLS_ROUTER")!=NULL;
        bool app_protocol=!strcmp(argv[4],"connect-app") || !strcmp(argv[4],"connect-app-reject");
        if (app_protocol || !strcmp(argv[4], "connect-net") || !strcmp(argv[4], "connect-net-verified") || !strcmp(argv[4], "connect-net-parsed") || !strcmp(argv[4], "connect-net-reject")) {
            struct pki_tls_owned_identity owned = {.key=key, .key_size=kn, .certificate=(char*)cert,.certificate_size=cn};
            struct der_source_test der_source={0};mbedtls_x509_crt_init(&der_source.chain);
            bool der_input=getenv("WENDY_TLS_DER_INPUT")!=NULL;
            bool der_corrupt=getenv("WENDY_TLS_DER_CORRUPT")!=NULL;
            if (!strcmp(argv[4], "connect-net-verified")) {
                assert(!wendy_pki_verify_identity(cert,cn,root,rn,key,kn,
                    "spiffe://wendy.sh/tenant/2558fd76-afc7-466e-9613-6b715296a526/device/00000000-0000-4000-8000-000000000004",
                    time(NULL),&owned.verified_until));
                assert(owned.verified_until>time(NULL));
            }
            if (app_protocol || !strcmp(argv[4], "connect-net-parsed") || !strcmp(argv[4], "connect-net-reject")) owned.verify_at = time(NULL);
            if(der_input) {
                assert(!wendy_pki_crypto_init());
                assert(!pki_parse_certificate_bundle(&der_source.chain,cert,cn,false));
                der_source.corrupt=der_corrupt;
                free(owned.certificate);owned.certificate=NULL;owned.certificate_size=0;
                owned.read_der=read_der_test;owned.der_context=&der_source;owned.verify_at=time(NULL);
                if(getenv("WENDY_TLS_DER_RANGES"))owned.read_der_range=read_der_range_test;
                if(getenv("WENDY_TLS_BOUNDED_SOURCE_HASH"))owned.hash_der=hash_der_test;
                owned.reserve_records_first=true;owned.input_reserve=24576;
                owned.input_reservation=mbedtls_calloc(1,owned.input_reserve);assert(owned.input_reservation);
                if(router_protocol)owned.public_chain=public_source_test(&der_source.chain,root,rn);
            }
            if (owned.verified_until || owned.verify_at) {
                owned.trust=root; owned.trust_capacity=rn+1;
            }
            key = NULL; cert = NULL;
            uint8_t *transferred_trust = owned.trust;
            wendy_pki_connection *c = NULL;
            bool native_stream=getenv("WENDY_TLS_ROUTER_STREAM")!=NULL;
            struct test_stream transport={.fd=-1};
            int connected;
            if(native_stream || (getenv("WENDY_TLS_ASYNC") && (router_protocol || app_protocol))) {
                transport.fd=socket(AF_INET,SOCK_STREAM,0);assert(transport.fd>=0);
                struct sockaddr_in addr={.sin_family=AF_INET,.sin_port=htons((uint16_t)strtoul(argv[5],NULL,10)),
                    .sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
                assert(!connect(transport.fd,(struct sockaddr*)&addr,sizeof addr));
                assert(!fcntl(transport.fd,F_SETFL,O_NONBLOCK));
                struct wendy_pki_stream io={.context=&transport,.read=stream_read,.write=stream_write,.wait=stream_wait};
                if(getenv("WENDY_TLS_ASYNC")){
                    if(!owned.verify_at)owned.verify_at=time(NULL);
                    connected=pki_tls_net_begin(&io,false,"2558fd76-afc7-466e-9613-6b715296a526",
                        "00000000-0000-4000-8000-000000000004",&owned,(struct wendy_conf_span){root,rn},app_protocol,&c);
                    if(!connected){
                        int r=1;unsigned steps=0;
                        while(r && ++steps<10000){
                            r=pki_tls_net_advance(c,app_protocol,"00000000-0000-4000-8000-000000000005");
                            if(r==-2 || r==-3){assert(stream_wait(&transport,r==-3,esp_timer_get_time()+3000000)>=0);r=1;}
                            else if(r<0){connected=-1;break;}
                        }
                        assert(steps<10000);
                    }
                }else connected=pki_tls_net_stream(&io,false,"2558fd76-afc7-466e-9613-6b715296a526",
                    "00000000-0000-4000-8000-000000000004",
                    getenv("WENDY_TLS_UNKNOWN_PEER") ? NULL : "00000000-0000-4000-8000-000000000005",
                    &owned,(struct wendy_conf_span){root,rn},&c);
            } else connected=pki_tls_net_connect("localhost", (unsigned)strtoul(argv[5], NULL, 10),
                "2558fd76-afc7-466e-9613-6b715296a526",
                "00000000-0000-4000-8000-000000000004",
                "00000000-0000-4000-8000-000000000005", &owned,
                (struct wendy_conf_span){root,rn}, router_protocol ? "wendy-local-mesh-ble/2" : app_protocol ? "wendy-app-mesh-tls/1" : "wendy-net-endpoint/2", &c);
            if(der_input) {
                assert(der_source.reads>0);
                if(!connected) {
                    unsigned count=0;
                    for(const mbedtls_x509_crt *part=&der_source.chain;part;part=part->next)count++;
                    assert(der_source.reads>count+1); /* On-demand presentation after full parsing. */
                    assert(!c->presented_chain && !c->config.MBEDTLS_PRIVATE(f_wendy_certificate_der));
                }
            }
            mbedtls_x509_crt_free(&der_source.chain);
            if (der_corrupt || getenv("WENDY_TLS_PUBLIC_CORRUPT") || !strcmp(argv[4], "connect-net-reject") || !strcmp(argv[4],"connect-app-reject")) {
                assert(connected && !c && !owned.key && !owned.certificate && !owned.trust);
                if(native_stream){assert(fcntl(transport.fd,F_GETFD)>=0);close(transport.fd);}
                if (transferred_trust) root=NULL;
                free(root); return 0;
            }
            assert(!connected);
            assert(c && !owned.key && !owned.certificate && !owned.key_size && !owned.trust);
            if (transferred_trust) {
                root = NULL;
            }
            if (router_protocol) {
                public_index_snapshot_test(c);
                struct wendy_pki_mesh_peer authenticated;
                assert((c->mesh_roots || c->roots.raw.len || c->public_anchor || c->lazy_trust) && (c->certificate.raw.len || c->public_chain));
                assert(!wendy_pki_mesh_authenticated_peer(c,&authenticated));
                assert(!strcmp(authenticated.device,"00000000-0000-4000-8000-000000000005"));
                assert(authenticated.expires==c->operator_expires && authenticated.spki_size>0);
                const mbedtls_x509_crt *own_chain=c->public_chain ?
                    &((struct der_source_test*)c->public_chain->context)->chain:&c->certificate;
                assert(c->public_chain ? !c->certificate.raw.len && c->authenticated_peer!=NULL : c->certificate.raw.len>0);
                const uint8_t *ders[8];size_t sizes[8],count=0;
                for(const mbedtls_x509_crt *p=own_chain;p && p->raw.len;p=p->next) {
                    assert(count<8);ders[count]=p->raw.p;sizes[count++]=p->raw.len;
                }
                c->mesh_deadline_us=esp_timer_get_time()+60000000;
                struct wendy_pki_mesh_peer reverified;
                assert(!wendy_pki_mesh_verify_bundle(c,ders,sizes,count,time(NULL),&reverified));
                assert(!strcmp(reverified.device,"00000000-0000-4000-8000-000000000004"));
                assert(wendy_pki_mesh_verify_bundle(c,ders,sizes,count,time(NULL)+7200,&reverified));

                uint8_t *tampered=malloc(sizes[0]);assert(tampered);
                memcpy(tampered,ders[0],sizes[0]);tampered[sizes[0]-1]^=1;ders[0]=tampered;
                assert(wendy_pki_mesh_verify_bundle(c,ders,sizes,count,time(NULL),&reverified));
                free(tampered);ders[0]=own_chain->raw.p;
                int bundle_size=wendy_pki_mesh_bundle(c,NULL,0);assert(bundle_size>0);
                char *own_bundle=malloc((size_t)bundle_size+1);assert(own_bundle);
                assert(wendy_pki_mesh_bundle(c,own_bundle,(size_t)bundle_size+1)==bundle_size);
                free(own_bundle);
                char description[1024];
                assert(wendy_pki_mesh_describe(c,description,sizeof description)>0);
                for(const mbedtls_x509_crt *part=own_chain;part && part->raw.len;part=part->next) {
                    uint8_t hash[32],chunk[1024];size_t total;
                    assert(!wendy_pki_sha256(part->raw.p,part->raw.len,hash));
                    for(size_t offset=0;offset<part->raw.len;offset+=1024) {
                        int n=wendy_pki_mesh_part(c,hash,offset,chunk,&total);
                        assert(n>0 && total==part->raw.len && !memcmp(chunk,part->raw.p+offset,n));
                    }
                    assert(wendy_pki_mesh_part(c,hash,1,chunk,&total)<0);
                    memset(hash,0,32);
                    assert(wendy_pki_mesh_part(c,hash,0,chunk,&total)<0);
                }
                if(c->public_chain) {
                    uint8_t chunk[1024];size_t total;
                    struct der_source_test *source=c->public_chain->context;
                    source->corrupt=true;
                    assert(wendy_pki_mesh_part(c,c->public_chain->hashes[1],0,chunk,&total)<0);
                    source->corrupt=false;

                    if(c->lazy_trust) {
                        assert(!c->roots.raw.len && source->trust_size);
                        source->trust[0]^=1;
                        assert(wendy_pki_mesh_verify_bundle(c,ders,sizes,count,time(NULL),&reverified));
                        source->trust[0]^=1;
                        assert(!wendy_pki_mesh_verify_bundle(c,ders,sizes,count,time(NULL),&reverified));
                    }
                    if(c->public_anchor) {
                        const mbedtls_x509_crt *anchor=&source->chain;
                        for(unsigned i=1;i<c->public_anchor;i++)anchor=anchor->next;
                        assert(anchor && anchor->raw.len && !c->roots.raw.len);
                        anchor->raw.p[anchor->raw.len-1]^=1;
                        assert(wendy_pki_mesh_verify_bundle(c,ders,sizes,count,time(NULL),&reverified));
                        anchor->raw.p[anchor->raw.len-1]^=1;
                        assert(!wendy_pki_mesh_verify_bundle(c,ders,sizes,count,time(NULL),&reverified));
                    }
                }

            } else {
                assert(!c->mesh_roots && !c->mesh_roots_size && !c->roots.raw.len);
                assert(!c->certificate.raw.len && !c->certificate.next);
            }
            unsigned peer_certs=0;
            for (const mbedtls_x509_crt *peer=mbedtls_ssl_get_peer_cert(&c->ssl); peer; peer=peer->next) peer_certs++;
            assert(router_protocol && !c->public_chain ? peer_certs>0 : peer_certs==0); /* Complete path and identity checked before compact-role release. */
            assert(c->operator_expires > time(NULL));
#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
            assert(c->ssl.MBEDTLS_PRIVATE(in_buf_len) < 20000);
#endif
            char reply[5]; size_t sent=0, received=0;
            while (sent<5) {
                int n=wendy_pki_write(c,&"hello"[sent],5-sent);
                if(n>0) sent+=n; else wait_io(c,n);
            }
            while (received<5) {
                int n=wendy_pki_read(c,reply+received,5-received);
                if(n>0) received+=n; else wait_io(c,n);
            }
            assert(!memcmp(reply,"world",5));
            bulk_echo_and_expiry(c);
            wendy_pki_close(c);
            if(native_stream){
                assert(transport.partial_reads && transport.partial_writes && transport.blocked_reads && transport.blocked_writes);
                assert(fcntl(transport.fd,F_GETFD)>=0);close(transport.fd);
            }
            free(root); return 0;
        }
        bool truncate = !strcmp(argv[4], "connect-truncated");
        assert(truncate || !strcmp(argv[4], "connect"));
        outbound((unsigned)strtoul(argv[5], NULL, 10), key, kn, cert, cn, root, rn, truncate);
        free(key); free(cert); free(root);
        return 0;
    }
    int listener = socket(AF_INET, SOCK_STREAM, 0); assert(listener >= 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    assert(!bind(listener, (struct sockaddr *)&address, sizeof address));
    socklen_t size = sizeof address; assert(!getsockname(listener, (struct sockaddr *)&address, &size));
    assert(!listen(listener, 1)); printf("%d\n", ntohs(address.sin_port)); fflush(stdout);
    int fd = accept(listener, NULL, NULL); close(listener); assert(fd >= 0);
    wendy_pki_connection *c = NULL;
    const char *mode = argv[4];
    bool owned_lan=!strncmp(mode,"owned-lan-",10);
    bool router_protocol=getenv("WENDY_TLS_ROUTER")!=NULL;
    bool native_app=!strncmp(mode,"app-net-",8);
    bool native_byte_stream=router_protocol && getenv("WENDY_TLS_ROUTER_STREAM");
    bool actor_agent=owned_lan && getenv("WENDY_TLS_AGENT_ACTOR");
    if (owned_lan || native_app || !strncmp(mode,"native-net-",11)) {
        struct pki_tls_owned_identity owned={.key=key,.key_size=kn,
            .certificate=(char*)cert,.certificate_size=cn,.verify_at=time(NULL),
            .trust=root,.trust_capacity=rn+1};
        struct der_source_test der_source={0};mbedtls_x509_crt_init(&der_source.chain);
        if(getenv("WENDY_TLS_DER_INPUT")) {
            assert(!wendy_pki_crypto_init());
            assert(!pki_parse_certificate_bundle(&der_source.chain,cert,cn,false));
            free(owned.certificate);owned.certificate=NULL;owned.certificate_size=0;
            owned.read_der=read_der_test;owned.der_context=&der_source;
            if(getenv("WENDY_TLS_DER_RANGES"))owned.read_der_range=read_der_range_test;
            if(getenv("WENDY_TLS_BOUNDED_SOURCE_HASH"))owned.hash_der=hash_der_test;
            owned.reserve_records_first=true;owned.input_reserve=owned_lan ? 26624:24576;
#if defined(WENDY_PKI_INPUT_SHRINK_HOST_TEST)
            owned.input_reservation=owned_lan ? pki_tls_input_take(owned.input_reserve):mbedtls_calloc(1,owned.input_reserve);
#else
            owned.input_reservation=mbedtls_calloc(1,owned.input_reserve);
#endif
            assert(owned.input_reservation);
            if(router_protocol)owned.public_chain=public_source_test(&der_source.chain,root,rn);
        }
        uint8_t preparation_cookie=0;
        bool preclaimed=owned_lan && !actor_agent && getenv("WENDY_TLS_NATIVE_PREPARE_LEASE");
        if(preclaimed){
            assert(pki_native_prepare_claim(&preparation_cookie,esp_timer_get_time()+5000000));
            owned.preparation_owner=&preparation_cookie;
        }
        struct test_stream transport={.fd=fd};
        struct agent_bio agent_transport;
        struct wendy_pki_stream io={.context=&transport,.read=stream_read,.write=stream_write,.wait=stream_wait};
        if(native_byte_stream)assert(!fcntl(fd,F_SETFL,O_NONBLOCK));
        int result=actor_agent ? agent_tls_test_begin(fd,&owned,(struct wendy_conf_span){root,rn},&agent_transport,&c):
            native_byte_stream ? pki_tls_net_stream(&io,true,
            "2558fd76-afc7-466e-9613-6b715296a526","00000000-0000-4000-8000-000000000004",
            NULL,&owned,(struct wendy_conf_span){root,rn},&c)
            : owned_lan ? pki_tls_accept_owned(&fd,&owned,
            (struct wendy_conf_span){root,rn},"2558fd76-afc7-466e-9613-6b715296a526",
            "00000000-0000-4000-8000-000000000004",&c,esp_timer_get_time()+5000000)
            : pki_tls_net_accept(&fd,"2558fd76-afc7-466e-9613-6b715296a526",
            "00000000-0000-4000-8000-000000000004",&owned,
            (struct wendy_conf_span){root,rn},router_protocol ? "wendy-local-mesh-ble/2" : native_app ? "wendy-app-mesh-tls/1" : "wendy-net-endpoint/2",&c);
        if(preclaimed){
            assert(!wendy_pki_handshake_busy());
            wendy_pki_handshake_release(&preparation_cookie);
        }
        mbedtls_x509_crt_free(&der_source.chain);
        assert((native_byte_stream || actor_agent ? fd>=0 : fd==-1) && !owned.key && !owned.certificate && !owned.trust && !owned.input_reservation);
        if (!strcmp(mode,"native-net-reject") || !strcmp(mode,"app-net-reject") || !strcmp(mode,"owned-lan-reject")) {
            assert(result && !c);
            if(native_byte_stream || actor_agent){assert(fcntl(fd,F_GETFD)>=0);close(fd);}
            return 0;
        }
        assert(!result && c && (owned_lan || !strcmp(c->mesh_peer,"00000000-0000-4000-8000-000000000005")));
        if(actor_agent){
            const char *expected=getenv("WENDY_TLS_EXPECT_ROLE");assert(expected);
            assert(c->peer_role==(!strcmp(expected,"operator") ? WENDY_PEER_ROLE_OPERATOR:WENDY_PEER_ROLE_DEVICE));
            assert(c->session_deadline_us>esp_timer_get_time());
        }
        if (router_protocol) {
            public_index_snapshot_test(c);
            assert(mbedtls_pk_get_bitlen(&c->key)>0);
            struct wendy_pki_mesh_peer authenticated;
            assert((c->mesh_roots || c->roots.raw.len || c->public_anchor || c->lazy_trust) && (c->certificate.raw.len || c->public_chain));
            assert(!wendy_pki_mesh_authenticated_peer(c,&authenticated));
            assert(!strcmp(authenticated.device,"00000000-0000-4000-8000-000000000005"));
        } else {
            assert(!c->mesh_roots && !c->roots.raw.len && !c->certificate.raw.len);
            assert(mbedtls_pk_get_bitlen(&c->key)==0);
        }
        assert((owned_lan || c->peer_role==WENDY_PEER_ROLE_DEVICE) && c->device_expires>time(NULL));
        if(owned_lan && getenv("WENDY_TLS_CLOSE_WITHOUT_APP")){
            wendy_pki_close(c);if(actor_agent)close(fd);return 0;
        }
        if(owned_lan && getenv("WENDY_TLS_LARGE_FIRST_RECORD")){
            uint8_t part[256];size_t total=0;
            while(total<16384){
                ssize_t n=wendy_pki_read(c,part,sizeof part);
                if(n<0){wait_io(c,(int)n);continue;}
                assert(n>0 && total+(size_t)n<=16384);
                for(ssize_t i=0;i<n;i++)assert(part[i]==(uint8_t)((total+(size_t)i)*29));
                total+=(size_t)n;
                if(total<16384){
                    assert(c->ssl.MBEDTLS_PRIVATE(in_offt)!=NULL);
                    if(getenv("WENDY_TLS_DEFER_INPUT_SHRINK"))assert(c->ssl.MBEDTLS_PRIVATE(in_buf_len)==26624);
                }
            }
            assert(c->ssl.MBEDTLS_PRIVATE(in_buf_len)==2048);
            assert(mbedtls_ssl_get_max_in_record_payload(&c->ssl)==16384);
            size_t used=0;while(used<6){ssize_t n=wendy_pki_write(c,&"big-ok"[used],6-used);if(n>0)used+=(size_t)n;else wait_io(c,(int)n);}
        }
        char request[5]; size_t received=0,sent=0;
        while(received<5) { int n=wendy_pki_read(c,request+received,5-received); if(n>0)received+=n;else wait_io(c,n); }
        assert(!memcmp(request,"hello",5));
        while(sent<5) { int n=wendy_pki_write(c,&"world"[sent],5-sent); if(n>0)sent+=n;else wait_io(c,n); }
        bulk_echo_and_expiry(c);
        if(actor_agent){
            int64_t flush_deadline=esp_timer_get_time()+3000000;
            while(agent_transport.channel.output.size)
                assert(!agent_bio_wait(&agent_transport,true,flush_deadline));
        }
        wendy_pki_close(c);
        if(native_byte_stream){
            assert(transport.partial_reads && transport.partial_writes);
            assert(fcntl(fd,F_GETFD)>=0);close(fd);
        }
        if(actor_agent){assert(agent_transport.reads>1 && agent_transport.writes>1 && agent_transport.steps>1);close(fd);}
        return 0;
    }

    bool stream_mode = !strncmp(mode, "stream-", 7);
    if (stream_mode) mode += 7;
    bool lite = !strncmp(mode, "lite-", 5);
    if (lite) mode += 5;
    bool lan = !strncmp(mode, "lan-", 4);
    if (lan) mode += 4;
    struct test_stream transport = {.fd = fd, .fail_wait = !strcmp(mode, "timeout")};
    const struct wendy_pki_stream stream = {
        .context = &transport, .read = stream_read, .write = stream_write, .wait = stream_wait,
    };
    int rc;
    bool owned_stream=stream_mode && getenv("WENDY_TLS_OWNED_STREAM");
    if (stream_mode) {
        assert(!fcntl(fd, F_SETFL, O_NONBLOCK));
        if(owned_stream){
            struct pki_tls_owned_identity owned={.key=key,.key_size=kn,
                .verify_at=time(NULL),.trust=root,.trust_capacity=rn+1};
            struct der_source_test source={0};mbedtls_x509_crt_init(&source.chain);
            assert(!wendy_pki_crypto_init());
            assert(!pki_parse_certificate_bundle(&source.chain,cert,cn,false));
            free(cert);cert=NULL;key=NULL;root=NULL;
            owned.read_der=read_der_test;owned.der_context=&source;
            if(getenv("WENDY_TLS_DER_RANGES"))owned.read_der_range=read_der_range_test;
            if(getenv("WENDY_TLS_BOUNDED_SOURCE_HASH"))owned.hash_der=hash_der_test;
            if(getenv("WENDY_TLS_MANAGEMENT_RECORDS")){
                owned.input_reserve=26624;owned.reserve_records_first=true;
            }
            if(getenv("WENDY_TLS_PHYSICAL_BLE_IO")){
                wendy_pki_work_enable();
                struct physical_ble_io_fixture io={.stream=&stream,.owned=&owned,
                    .roots={owned.trust,rn},.connection=&c,.result=-1};
                assert(wendy_pki_io_work_submit(physical_ble_io_accept,&io));
                assert(wendy_pki_io_work_poll() && wendy_pki_io_work_idle());
                rc=io.result;
            }else{
            rc=pki_tls_accept_owned_stream(&stream,&owned,
                (struct wendy_conf_span){owned.trust,rn},
                "2558fd76-afc7-466e-9613-6b715296a526",
                "00000000-0000-4000-8000-000000000004",
                &c,esp_timer_get_time()+3000000);
            }
            assert(!owned.key && !owned.certificate && !owned.trust);
            mbedtls_x509_crt_free(&source.chain);
        }else rc = pki_tls_accept_stream(&stream, key, kn, (struct wendy_conf_span){cert,cn},
            (struct wendy_conf_span){root, rn}, "2558fd76-afc7-466e-9613-6b715296a526",
            &c, esp_timer_get_time() + 3000000);
    } else {
        rc = (lite ? pki_tls_accept_lite : lan ? pki_tls_accept_lan : pki_tls_accept)(fd, key, kn, (struct wendy_conf_span){cert,cn}, (struct wendy_conf_span){root, rn},
            "2558fd76-afc7-466e-9613-6b715296a526", &c, esp_timer_get_time() + 3000000);
    }
    free(key); free(cert); free(root);
    if (!strcmp(mode, "reject") || !strcmp(mode, "timeout")) {
        if (c) wendy_pki_close(c);
        if (stream_mode) {
            assert(fcntl(fd, F_GETFD) >= 0);
            if (transport.fail_wait) assert(transport.read_waits + transport.write_waits > 0);
            close(fd);
        }
        return rc ? 0 : 1;
    }
    if (rc) return 2;
#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
    assert(c->ssl.MBEDTLS_PRIVATE(in_buf_len) >= (owned_stream ? 2048 : 16384));
    assert(c->ssl.MBEDTLS_PRIVATE(in_buf_len) < (owned_stream ? 28000 : 20000));
    assert(mbedtls_ssl_get_max_in_record_payload(&c->ssl) == 16384);
    /* TLS 1.3 reserves one byte for its inner content type. */
    assert(mbedtls_ssl_get_max_out_record_payload(&c->ssl) == MBEDTLS_SSL_OUT_CONTENT_LEN - 1);
#endif
    assert(wendy_pki_get_peer_role(c) == (!strcmp(mode, "valid-device") ? WENDY_PEER_ROLE_DEVICE : WENDY_PEER_ROLE_OPERATOR));
    if (stream_mode) { stream_exchange(c, &transport); return 0; }
    if (!strcmp(mode, "valid-device"))
        assert(pki_relay_grant(c, NULL, esp_timer_get_time() + 3000000) == -1);
    if (argc == 8) {
        size_t tn;
        unsigned char *raw = load(argv[5], &tn);
        assert(tn == 145);
        struct wendy_lite_trust trust = {.count = 1};
        trust.keys[0].id_size = 4;
        memcpy(trust.keys[0].id, "test", 4);
        memcpy(trust.keys[0].public_key, raw, 65);
        memcpy(trust.session, raw + 65, 16);
        memcpy(trust.grant_hash, raw + 81, 32);
        memcpy(c->device_hash, raw + 113, 32);
        c->device_expires = (time_t)strtoll(argv[6], NULL, 10);
        free(raw);
        rc = pki_relay_grant(c, &trust, esp_timer_get_time() + 3000000);
        if (!strcmp(mode, "relay-reject")) {
            wendy_pki_close(c);
            return rc ? 0 : 6;
        }
        if (rc) { wendy_pki_close(c); return 7; }
        int64_t expected = strtoll(argv[7], NULL, 10);
        int64_t remaining = (c->relay_expires_us - esp_timer_get_time()) / 1000000;
        assert(llabs(remaining - (expected - time(NULL))) <= 1);
        // The session uses a monotonic cutoff even after the clock is corrected.
        clock_advance = c->relay_expires_us - esp_timer_get_time() + 1;
        assert(wendy_pki_read(c, &byte, 1) == -1);
        assert(wendy_pki_write(c, "x", 1) == -1);
        wendy_pki_close(c);
        return 0;
    }
    fd = wendy_pki_detach(c);
    if (!strcmp(mode, "truncate") || !strcmp(mode, "extra")) {
        if (fd < 0) { wendy_pki_close(c); return 0; } close(fd); return 3;
    }
    if (fd < 0) { wendy_pki_close(c); return 4; }
    // close_notify completed without consuming bytes from the next protocol.
    assert(fcntl(fd, F_SETFL, 0) == 0);
    char raw[3]; int ok = recv(fd, raw, sizeof raw, MSG_WAITALL) == 3 && !memcmp(raw, "raw", 3);
    close(fd); return ok ? 0 : 5;
}

#include "tls_cv_trace_fixture.h"
int main(int argc,char **argv)
{
    if(argc>1)cv_trace_begin(argv[1],false);
    bool workspace=getenv("WENDY_TLS_INPUT_WORKSPACE")!=NULL;
    if(workspace){assert(getenv("WENDY_TLS_NORMAL_ONLY"));wendy_pki_input_workspace_active(true);}

    if(getenv("WENDY_TLS_NORMAL_ONLY")){
        /* The initial HTTPS allocation is genuinely small; it does not need
         * an ordinary16KiB buffer first. The accepted record limit stays16KiB. */
        int mbedtls_ssl_setup_small_input(mbedtls_ssl_context *,const mbedtls_ssl_config *);
        assert(!wendy_pki_crypto_init());
        mbedtls_ssl_context ssl;mbedtls_ssl_config config;
        mbedtls_ssl_init(&ssl);mbedtls_ssl_config_init(&config);
        assert(!mbedtls_ssl_config_defaults(&config,MBEDTLS_SSL_IS_CLIENT,
            MBEDTLS_SSL_TRANSPORT_STREAM,MBEDTLS_SSL_PRESET_DEFAULT));
        assert(!mbedtls_ssl_setup_small_input(&ssl,&config));
        assert(ssl.MBEDTLS_PRIVATE(in_buf_len)==2048);
        assert(mbedtls_ssl_get_max_in_record_payload(&ssl)==16384);
        mbedtls_ssl_free(&ssl);mbedtls_ssl_config_free(&config);
    }
    unsigned repeat=1;const char *count=getenv("WENDY_TLS_NORMAL_REPEAT");
    if(count){
        assert(getenv("WENDY_TLS_NORMAL_ONLY") && !strcmp(getenv("WENDY_TLS_NORMAL_ONLY"),"1"));
        repeat=(unsigned)strtoul(count,NULL,10);assert(repeat>=1 && repeat<=8);
    }
    for(unsigned i=0;i<repeat;i++){int result=tls_test_once(argc,argv);if(result)return result;}
    if(workspace){
        assert(wendy_pki_input_workspace_cached_bytes()==PKI_TLS_INPUT_RESERVE);
        wendy_pki_input_workspace_active(false);
        assert(!wendy_pki_input_workspace_cached_bytes());
    }
    return 0;
}
