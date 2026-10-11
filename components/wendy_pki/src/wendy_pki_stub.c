#include "wendy_pki.h"
void wendy_pki_builtin_trust(bool *ready, bool *tsa_ready)
{
    *ready = false;
    *tsa_ready = false;
}
esp_err_t wendy_pki_sync_time(unsigned server, const uint8_t *reply, size_t size,
                            bool *synchronized, int64_t *seconds)
{
    (void)server; (void)reply; (void)size;
    *synchronized = false; *seconds = 0;
    return ESP_ERR_NOT_SUPPORTED;
}
esp_err_t wendy_pki_challenge(bool status_only, char nonce_hex[65], bool *enrolled)
{
    (void)status_only;
    (void)nonce_hex;
    (void)enrolled;
    return ESP_ERR_NOT_SUPPORTED;
}
