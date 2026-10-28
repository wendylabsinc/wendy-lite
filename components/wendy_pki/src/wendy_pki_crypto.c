#include "wendy_pki_crypto.h"
#include "wendy_pki_alloc.h"
#include "wendy_pki_work.h"
#include "wendy_net_alloc.h"
#include <mbedtls/platform.h>
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#include <mbedtls/pk.h>
#include <psa/crypto.h>
#include <psa/crypto_extra.h>
#if ESP_PLATFORM
#include "sdkconfig.h"
#include "esp_heap_caps.h"
#endif

/* PSA tables are shared by baseline and mesh key users. Their metadata must
 * never inherit one temporary context's owner; actual key material still does.
 * Preserve external placement without borrowing or mutating the caller scope. */
void *wendy_pki_crypto_shared_calloc(size_t count,size_t bytes)
{
#if ESP_PLATFORM
    if(heap_caps_get_total_size(MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT))
        return wendy_net_memory_unscoped_calloc_in(count,bytes,WENDY_NET_MEMORY_EXTERNAL);
#elif defined(WENDY_PKI_MEMORY_HOST_SCOPE_TEST)
    wendy_net_memory_snapshot_t state;wendy_net_runtime_memory_snapshot(&state);
    if(state.external_enabled)
        return wendy_net_memory_unscoped_calloc_in(count,bytes,WENDY_NET_MEMORY_EXTERNAL);
#else
    return calloc(count,bytes);
#endif
#if ESP_PLATFORM || defined(WENDY_PKI_MEMORY_HOST_SCOPE_TEST)
    return wendy_net_memory_unscoped_calloc(count,bytes);
#endif
}

#if ESP_PLATFORM
#include "esp_private/startup_internal.h"
#include "esp_heap_caps.h"
/* IDF initializes PSA at system-init priority 104, before app_main and before
 * compiler TLS is available. Install once before that and preserve one pointer
 * ABI throughout startup, management and later mesh scopes. */
static int memory_status = -1;
static atomic_bool task_scopes_ready;
void *wendy_pki_scoped_calloc(size_t count,size_t bytes)
{
    if(atomic_load(&task_scopes_ready)){
        wendy_net_memory_scope_t scope=wendy_net_memory_scope_current();
        /* A charged scope always retains admission/placement, even closed. */
        if(scope.owner)return wendy_net_memory_scoped_calloc(count,bytes);
    }
    /* Baseline TLS on PSRAM boards previously used the external-only library
     * mode. Preserve that policy without changing generic uncharged helpers.
     * Before PSRAM registration, use the ordinary early-startup heap. */
    if(heap_caps_get_total_size(MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT))
        return wendy_net_memory_unscoped_calloc_in(count,bytes,WENDY_NET_MEMORY_EXTERNAL);
    return wendy_net_memory_unscoped_calloc(count,bytes);
}
void wendy_pki_scoped_free(void *ptr){wendy_net_memory_scoped_free(ptr);}
ESP_SYSTEM_INIT_FN(wendy_pki_memory, SECONDARY, BIT(0), 102)
{
    memory_status=mbedtls_platform_set_calloc_free(
        wendy_pki_scoped_calloc,wendy_pki_scoped_free);
    /* Priority102 precedes IDF's PSA initialization104 and app/Wi-Fi startup.
     * Both callbacks use the same prefix/free ABI. Never change it later. */
    if(!memory_status && mbedtls_psa_set_key_slot_table_allocator(wendy_pki_crypto_shared_calloc)!=PSA_SUCCESS)
        memory_status=-1;
    return memory_status ? ESP_FAIL:ESP_OK;
}
int wendy_pki_memory_init(void)
{
    if(memory_status)return -1;
    atomic_store(&task_scopes_ready,true); /* Called first in app_main, before application tasks. */
    return 0;
}
#else
int wendy_pki_memory_init(void){return 0;}
#endif

/* Both ordinary OQS objects and native ML-DSA heap temporaries use these
 * matching ownership prefixes. No dependency source or global libc hook. */
void *wendy_pki_oqs_malloc(size_t bytes)
{
    /* mldsa-native's polynomial/vector types require 32-byte alignment. Keep
     * padding and the base-pointer slot in the same charged allocation. */
    const size_t extra=31+sizeof(void *);
    if(!bytes || bytes>SIZE_MAX-extra)return NULL;
    unsigned char *base=pki_owned_malloc(bytes+extra);
    if(!base)return NULL;
    uintptr_t aligned=((uintptr_t)(base+sizeof(void *))+31)&~(uintptr_t)31;
    void *pointer=(void *)aligned;
    memcpy((unsigned char *)pointer-sizeof base,&base,sizeof base);
    return pointer;
}
void wendy_pki_oqs_free(void *ptr)
{
    if(!ptr)return;
    void *base;
    memcpy(&base,(unsigned char *)ptr-sizeof base,sizeof base);
    pki_owned_free(base);
}
#if ESP_PLATFORM
/* Strong overrides for the pinned ESP port's weak OQS_PLATFORM_MEM_HOOKS. */
void *oqs_platform_malloc(size_t bytes){return pki_owned_malloc(bytes);}
void *oqs_platform_calloc(size_t count,size_t bytes){return pki_owned_calloc(count,bytes);}
void oqs_platform_free(void *ptr){pki_owned_free(ptr);}
#endif

static pthread_once_t crypto_once = PTHREAD_ONCE_INIT;
static int crypto_status = -1;
static void init_crypto(void)
{
    crypto_status = psa_crypto_init() == PSA_SUCCESS ? 0 : -1;
}

int wendy_pki_crypto_init(void)
{
    return !wendy_pki_memory_init() && pthread_once(&crypto_once, init_crypto) == 0 ? crypto_status : -1;
}

static void cleanup_crypto(void *unused)
{
    (void)unused;
    size_t freed=0;
    (void)mbedtls_psa_trim_empty_key_slots(&freed);
}
void wendy_pki_crypto_cleanup(void)
{
#if ESP_PLATFORM && CONFIG_WENDY_PKI
    /* Baseline facade executes synchronously on the caller. Native actor
     * activation is rejected until the serialized worker layer is present. */
    (void)wendy_pki_work_run(cleanup_crypto,NULL);
#else
    cleanup_crypto(NULL);
#endif
}

int wendy_pki_sha256(const uint8_t *data, size_t size, uint8_t hash[32])
{
    size_t written = 0;
    return !wendy_pki_crypto_init() &&
           psa_hash_compute(PSA_ALG_SHA_256, data, size, hash, 32, &written) == PSA_SUCCESS &&
           written == 32 ? 0 : -1;
}

int wendy_pki_generate_key_der(uint8_t *buffer, size_t capacity)
{
    if (!buffer || !capacity || wendy_pki_crypto_init()) return -1;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 256);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    int result = -1;
    if (psa_generate_key(&attributes, &key) == PSA_SUCCESS &&
        !mbedtls_pk_copy_from_psa(key, &pk))
        result = mbedtls_pk_write_key_der(&pk, buffer, capacity);
    mbedtls_pk_free(&pk);
    psa_destroy_key(key);
    psa_reset_key_attributes(&attributes);
    return result;
}
