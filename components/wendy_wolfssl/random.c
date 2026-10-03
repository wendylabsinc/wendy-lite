#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/settings.h>
#ifdef ESP_PLATFORM
#include "esp_random.h"
#endif
/* OPENSSL_EXTRA's RAND_poll also calls wc_GenerateSeed directly. */
int wc_GenerateSeed(OS_Seed *os, byte *out, word32 size)
{
    (void)os;
#ifdef ESP_PLATFORM
    esp_fill_random(out, size);
#else
    return wendy_pki_host_random(out, size);
#endif
    return 0;
}
