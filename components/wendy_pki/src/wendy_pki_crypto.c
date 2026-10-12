#include "wendy_pki_verify.h"
#ifdef ESP_PLATFORM
#include "esp_random.h"
#else
#include <mbedtls/entropy.h>
#endif
int wendy_pki_rng(void *context, unsigned char *out, size_t size)
{
    (void)context;
#ifdef ESP_PLATFORM
    esp_fill_random(out, size);
    return 0;
#else
    mbedtls_entropy_context entropy;
    mbedtls_entropy_init(&entropy);
    int result = 0;
    while (size) {
        size_t n = size > MBEDTLS_ENTROPY_BLOCK_SIZE ? MBEDTLS_ENTROPY_BLOCK_SIZE : size;
        result = mbedtls_entropy_func(&entropy, out, n);
        if (result) break;
        out += n; size -= n;
    }
    mbedtls_entropy_free(&entropy);
    return result;
#endif
}

#if CONFIG_WENDY_PKI_WOLFSSL
#include <pthread.h>
#include <wolfssl/ssl.h>
static pthread_once_t backend_once = PTHREAD_ONCE_INIT;
static int backend_ready;
static void init_backend(void) { backend_ready = wolfSSL_Init() == WOLFSSL_SUCCESS; }
int wendy_pki_backend_init(void)
{
    pthread_once(&backend_once, init_backend);
    return backend_ready ? 0 : -1;
}
#endif
