#include "wendy_pki.h"
esp_err_t wendy_pki_challenge(bool status_only, char nonce_hex[65], bool *enrolled)
{
    (void)status_only;
    (void)nonce_hex;
    (void)enrolled;
    return ESP_ERR_NOT_SUPPORTED;
}
