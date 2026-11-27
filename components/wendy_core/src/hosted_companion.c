#include "hosted_companion.h"

#include <stdio.h>
#include "esp_hosted.h"
#include "esp_hosted_misc.h"
#include "esp_hosted_ota.h"
#include "esp_log.h"

static const char *TAG = "wendy_radio_ota";
/* Accessed by the WendyCom app-push delegate under its single upload owner. */
static size_t expected_size, written;

static bool supports_staged_update(void)
{
    esp_hosted_coprocessor_fwver_t version = {0};
    return esp_hosted_get_coprocessor_fwversion(&version) == ESP_OK &&
           (version.major1 > 2 || (version.major1 == 2 && version.minor1 >= 6));
}

WendyComResult hosted_companion_get(WendyComHostedCompanionInfo *out)
{
    esp_hosted_app_desc_t desc = {0};
    if (esp_hosted_get_coprocessor_app_desc(&desc) == ESP_OK) {
        snprintf(out->build_id, sizeof out->build_id, "%.*s",
                 (int)sizeof out->build_id - 1, desc.version);
        return WendyComResult_WENDY_COM_RESULT_OK;
    }

    /* Stock firmware may support staged OTA without the descriptor RPC.
     * An empty ID then means it cannot already be our versioned build. */
    return supports_staged_update() ? WendyComResult_WENDY_COM_RESULT_OK
                                    : WendyComResult_WENDY_COM_RESULT_BAD_STATE;
}

WendyComResult hosted_companion_begin(size_t size)
{
    if (size == 0 || size > 4 * 1024 * 1024)
        return WendyComResult_WENDY_COM_RESULT_BAD_APP_SIZE;
    /* Older Hosted radios activate inside OTA end. Require the separate
     * activate operation so an interrupted upload can never switch images. */
    if (!supports_staged_update())
        return WendyComResult_WENDY_COM_RESULT_BAD_STATE;
    esp_err_t err = esp_hosted_slave_ota_begin();
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Could not begin companion OTA: %s", esp_err_to_name(err));
        return WendyComResult_WENDY_COM_RESULT_UNKNOWN_ERROR;
    }
    expected_size = size;
    written = 0;
    return WendyComResult_WENDY_COM_RESULT_OK;
}

bool hosted_companion_pending(void)
{
    return expected_size != 0;
}

WendyComResult hosted_companion_write(size_t offset, const uint8_t *data, size_t size)
{
    if (!size || offset != written || size > expected_size - written)
        return WendyComResult_WENDY_COM_RESULT_BAD_APP_SIZE;
    // ESP-Hosted copies into an RPC payload without changing the source bytes.
    esp_err_t err = esp_hosted_slave_ota_write((uint8_t *)data, size);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Could not write companion OTA: %s", esp_err_to_name(err));
        return WendyComResult_WENDY_COM_RESULT_UNKNOWN_ERROR;
    }
    written += size;
    return WendyComResult_WENDY_COM_RESULT_OK;
}

WendyComResult hosted_companion_end(void)
{
    bool complete = written == expected_size;
    expected_size = 0;
    esp_err_t err = esp_hosted_slave_ota_end();
    if (!complete)
        return WendyComResult_WENDY_COM_RESULT_BAD_APP_SIZE;
    if (err == ESP_OK)
        err = esp_hosted_slave_ota_activate();
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Could not finish companion OTA: %s", esp_err_to_name(err));
        return WendyComResult_WENDY_COM_RESULT_UNKNOWN_ERROR;
    }
    return WendyComResult_WENDY_COM_RESULT_OK;
}

void hosted_companion_abort(void)
{
    // Release the staged OTA handle without activating the written partition.
    expected_size = 0;
    (void)esp_hosted_slave_ota_end();
}
