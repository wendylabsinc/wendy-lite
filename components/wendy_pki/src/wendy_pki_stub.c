#include "wendy_pki.h"
void wendy_pki_builtin_trust(bool *ready, bool *tsa_ready)
{
    *ready = false;
    *tsa_ready = false;
}
esp_err_t wendy_pki_sync_time(const char *server, const uint8_t *reply, size_t size,
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

esp_err_t wendy_pki_reset(const char *expected_device_id, const char *nonce_hex)
{
    (void)expected_device_id; (void)nonce_hex;
    return ESP_ERR_NOT_SUPPORTED;
}

bool wendy_pki_reset_in_progress(void) { return false; }

esp_err_t wendy_pki_accept_stream(const struct wendy_pki_stream *stream,
                                wendy_pki_connection **connection)
{
    if (connection) *connection = NULL;
    if (!stream || !stream->read || !stream->write || !stream->wait || !connection)
        return ESP_ERR_INVALID_ARG;
    return ESP_ERR_NOT_SUPPORTED;
}

bool wendy_pki_pending(wendy_pki_connection *connection)
{
    (void)connection;
    return false;
}

esp_err_t wendy_pki_validate_setup(const WendyConfEnrollment *cfg,
                                 const struct wendy_conf_enrollment_data *data)
{
    (void)cfg; (void)data;
    return ESP_ERR_NOT_SUPPORTED;
}
