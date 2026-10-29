#pragma once
#include <stdlib.h>
#if ESP_PLATFORM
#include "wendy_net_memory.h"
void *wendy_pki_scoped_calloc(size_t count,size_t bytes);
void wendy_pki_scoped_free(void *ptr);
/* PKI-owned buffers retain the initiating mesh/management owner. These must
 * never consume raw storage/HTTP/certificate-source transfer pointers. */
static inline void *pki_owned_malloc(size_t bytes)
{return wendy_pki_scoped_calloc(1,bytes);}
static inline void *pki_owned_calloc(size_t count,size_t bytes)
{return wendy_pki_scoped_calloc(count,bytes);}
static inline void pki_owned_free(void *ptr)
{wendy_pki_scoped_free(ptr);}
#elif defined(WENDY_PKI_MEMORY_HOST_SCOPE_TEST)
/* Host allocation-hook fixtures exercise the same PKI/library pointer ABI. */
#include <mbedtls/platform.h>
static inline void *pki_owned_malloc(size_t bytes){return mbedtls_calloc(1,bytes);}
static inline void *pki_owned_calloc(size_t count,size_t bytes){return mbedtls_calloc(count,bytes);}
static inline void pki_owned_free(void *ptr){mbedtls_free(ptr);}
#else
/* Existing portable PKI APIs/tests retain libc ownership. */
static inline void *pki_owned_malloc(size_t bytes){return malloc(bytes);}
static inline void *pki_owned_calloc(size_t count,size_t bytes){return calloc(count,bytes);}
static inline void pki_owned_free(void *ptr){free(ptr);}
#endif
