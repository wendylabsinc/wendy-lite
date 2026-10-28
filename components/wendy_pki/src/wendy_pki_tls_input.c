#include "wendy_pki_tls_input.h"
#include "wendy_net_memory.h"
#include <mbedtls/platform.h>
#include <mbedtls/platform_util.h>
#include <pthread.h>
static pthread_mutex_t lock=PTHREAD_MUTEX_INITIALIZER;
static bool enabled;
static unsigned char *cached,*loan;
static bool loan_cacheable;
static wendy_net_memory_scope_t cache_scope;
static bool matching_scope(void)
{
    wendy_net_memory_scope_t scope=wendy_net_memory_scope_current();
    return scope.owner==cache_scope.owner && scope.placement==cache_scope.placement;
}
void wendy_pki_input_workspace_active(bool active)
{
    pthread_mutex_lock(&lock);
    if(active && !enabled)cache_scope=wendy_net_memory_scope_current();
    enabled=active;
    if(!active){mbedtls_free(cached);cached=NULL;loan_cacheable=false;}
    else if(!cached && !loan && matching_scope())cached=mbedtls_calloc(1,PKI_TLS_INPUT_RESERVE);
    pthread_mutex_unlock(&lock);
}
size_t wendy_pki_input_workspace_cached_bytes(void)
{
    pthread_mutex_lock(&lock);size_t bytes=cached ? PKI_TLS_INPUT_RESERVE:0;
    pthread_mutex_unlock(&lock);return bytes;
}
unsigned char *wendy_pki_input_workspace_borrow(size_t *capacity)
{
    if(!capacity)return NULL;
    *capacity=0;
    pthread_mutex_lock(&lock);
    unsigned char *p=NULL;
    if(enabled && cached && !loan && matching_scope()){
        p=cached;cached=NULL;loan=p;loan_cacheable=true;*capacity=PKI_TLS_INPUT_RESERVE;
    }
    pthread_mutex_unlock(&lock);return p;
}
void wendy_pki_input_workspace_release(unsigned char *p)
{
    pki_tls_input_return(p,PKI_TLS_INPUT_RESERVE);
}
unsigned char *pki_tls_input_take(size_t size)
{
    pthread_mutex_lock(&lock);
    unsigned char *p;
    /* Baseline management can lend this idle mesh-owned block without changing
     * its allocator owner. Net-off stops recaching; the original ledger stays
     * draining until the finite TLS loan returns. Certificate workspace borrow
     * above deliberately retains exact owner/placement matching. */
    wendy_net_memory_scope_t scope=wendy_net_memory_scope_current();
    bool matching=enabled && (!scope.owner || matching_scope());
    bool from_cache=matching && size==PKI_TLS_INPUT_RESERVE && cached;
    if(from_cache){p=cached;cached=NULL;}
    else p=mbedtls_calloc(1,size);
    if(size==PKI_TLS_INPUT_RESERVE && p && !loan){
        /* A baseline handshake can start before mesh enables its reserve.
         * Track that live allocation too, so enabling does not allocate a
         * second 26KiB block in the middle of certificate verification.
         * A foreign/unowned allocation is never adopted into the mesh cache. */
        loan=p;loan_cacheable=from_cache || (enabled && matching_scope());
    }
    pthread_mutex_unlock(&lock);return p;
}
int pki_tls_input_recycle(void *context,unsigned char *p,size_t size)
{
    (void)context;
    if(!p)return 0;
    pthread_mutex_lock(&lock);
    bool ours=loan==p;
    bool keep=ours && loan_cacheable && enabled && size==PKI_TLS_INPUT_RESERVE && !cached;
    if(ours){loan=NULL;loan_cacheable=false;}
    if(keep)cached=p;
    pthread_mutex_unlock(&lock);return keep;
}
void pki_tls_input_return(unsigned char *p,size_t size)
{
    if(!p)return;
    mbedtls_platform_zeroize(p,size);
    if(!pki_tls_input_recycle(NULL,p,size))mbedtls_free(p);
}

void pki_tls_input_discard_cached(void)
{
    pthread_mutex_lock(&lock);mbedtls_free(cached);cached=NULL;
    pthread_mutex_unlock(&lock);
}
