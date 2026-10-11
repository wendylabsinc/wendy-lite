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
