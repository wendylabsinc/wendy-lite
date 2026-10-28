/* Stream deadline hints retain TLS direction, failures and the initiating scope. */
#include "wendy_pki_internal.h"
#include "esp_timer.h"
#include <assert.h>

static int stream_control_read(mbedtls_ssl_context *,unsigned char *,size_t);
#define mbedtls_ssl_read stream_control_read
#include "../src/wendy_pki_tls.c"
#undef mbedtls_ssl_read

static int64_t now;
static bool resetting,advance_after_hint;
static wendy_net_memory_t owner=WENDY_NET_MEMORY_INITIALIZER;
static wendy_net_memory_t caller=WENDY_NET_MEMORY_INITIALIZER;
struct attempt {
    int read_result,wait_result;
    bool partial,reset_on_wait,spurious,boundary_hint;
    unsigned reads,waits;
};
static struct attempt *active;
int64_t esp_timer_get_time(void)
{
    int64_t sampled=now;
    if(advance_after_hint){now=100;advance_after_hint=false;}
    return sampled;
}
bool wendy_pki_reset_in_progress(void){return resetting;}
static int stream_control_read(mbedtls_ssl_context *ssl,unsigned char *out,size_t size)
{
    (void)ssl;
    assert(wendy_net_memory_scope_current().owner==&owner);
    active->reads++;
    if(active->partial && active->reads==1){assert(size==4);*out='W';return 1;}
    if(active->spurious && active->reads==2){now=100;return 0;}
    if(active->read_result!=MBEDTLS_ERR_SSL_WANT_READ &&
       active->read_result!=MBEDTLS_ERR_SSL_WANT_WRITE)now=100;
    return active->read_result;
}
static int stream_control_wait(void *context,bool writing,int64_t deadline)
{
    assert(context==active && deadline==100);
    assert(wendy_net_memory_scope_current().owner==&caller);
    assert(writing==(active->read_result==MBEDTLS_ERR_SSL_WANT_WRITE));
    active->waits++;
    now=active->spurious || active->boundary_hint ? deadline-1:deadline;
    advance_after_hint=active->boundary_hint;
    if(active->reset_on_wait)resetting=true;
    return active->wait_result;
}
static void run(struct attempt attempt,int expected)
{
    active=&attempt;now=0;resetting=false;advance_after_hint=false;
    wendy_pki_connection connection={.fd=-1,
        .allocation_scope={.owner=&owner,.placement=WENDY_NET_MEMORY_INTERNAL},
        .stream={.context=&attempt,.wait=stream_control_wait}};
    wendy_net_memory_scope_t previous=wendy_net_memory_scope_enter(&caller,WENDY_NET_MEMORY_INTERNAL);
    uint8_t header[4];assert(read_all(&connection,header,sizeof header,100)==expected);
    assert(wendy_net_memory_scope_current().owner==&caller);
    wendy_net_memory_scope_leave(previous);
    assert(attempt.reads && now==100);
    bool retry=attempt.read_result==MBEDTLS_ERR_SSL_WANT_READ ||
        attempt.read_result==MBEDTLS_ERR_SSL_WANT_WRITE;
    assert(attempt.waits==(retry ? 1U:0U));
}
int main(void)
{
    assert(wendy_net_memory_open(&owner,65536,false));
    assert(wendy_net_memory_open(&caller,65536,false));
    run((struct attempt){.read_result=MBEDTLS_ERR_SSL_WANT_READ},READ_ALL_IDLE_TIMEOUT);
    run((struct attempt){.read_result=MBEDTLS_ERR_SSL_WANT_WRITE},-1);
    run((struct attempt){.read_result=MBEDTLS_ERR_SSL_WANT_READ,.boundary_hint=true},READ_ALL_IDLE_TIMEOUT);
    run((struct attempt){.read_result=MBEDTLS_ERR_SSL_WANT_WRITE,.boundary_hint=true},-1);
    run((struct attempt){.read_result=MBEDTLS_ERR_SSL_WANT_READ,.wait_result=-1},-1);
    run((struct attempt){.read_result=MBEDTLS_ERR_SSL_WANT_READ,.partial=true},-1);
    run((struct attempt){.read_result=MBEDTLS_ERR_SSL_WANT_READ,.reset_on_wait=true},-1);
    run((struct attempt){.read_result=MBEDTLS_ERR_SSL_WANT_READ,.spurious=true},-1);
    run((struct attempt){.read_result=0},-1);
    run((struct attempt){.read_result=MBEDTLS_ERR_NET_CONN_RESET},-1);
    run((struct attempt){.read_result=MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY},-1);
    wendy_net_memory_close(&owner);wendy_net_memory_close(&caller);
    assert(wendy_net_memory_drained(&owner) && wendy_net_memory_drained(&caller));
    puts("PASS stream idle deadlines preserve read/write direction, reset/error results and TLS allocation scope");
    return 0;
}
