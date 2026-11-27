#include "hosted_companion.h"

#include <stdio.h>
#include "esp_hosted_misc.h"
#include "esp_hosted_ota.h"
#include "esp_log.h"

static const char *TAG = "wendy_radio_ota";
enum ota_protocol { OTA_UNAVAILABLE, OTA_LEGACY, OTA_STAGED_NO_DESCRIPTOR, OTA_STAGED };

/* Added to the transport by the ESP-Hosted patch in wendy_wifi. */
bool wendy_hosted_peer_fw_version(uint32_t *version);

/* Accessed by the WendyCom app-push delegate under its single upload owner. */
static size_t expected_size, written;
static enum ota_protocol update_protocol;
static bool interrupted_legacy_update;

static enum ota_protocol companion_ota_protocol(void)
{
    uint32_t version;
    if (!wendy_hosted_peer_fw_version(&version))
        return OTA_UNAVAILABLE;

    /* The FireBeetle factory image does not include the version in its
     * transport hello. It supports OTA Begin/Write/End, and End activates. */
    if (version < 0x020600)
        return OTA_LEGACY;
    /* Staged activation arrived in 2.6.0. The descriptor RPC arrived in 2.6.7. */
    if (version < 0x020607)
        return OTA_STAGED_NO_DESCRIPTOR;
    return OTA_STAGED;
}

WendyComResult hosted_companion_get(WendyComHostedCompanionInfo *out)
{
    enum ota_protocol protocol = companion_ota_protocol();
    if (protocol == OTA_UNAVAILABLE)
        return WendyComResult_WENDY_COM_RESULT_BAD_STATE;
    if (protocol != OTA_STAGED) {
        out->build_id[0] = '\0';
        return WendyComResult_WENDY_COM_RESULT_OK;
    }

    esp_hosted_app_desc_t desc = {0};
    if (esp_hosted_get_coprocessor_app_desc(&desc) != ESP_OK || !desc.version[0])
        return WendyComResult_WENDY_COM_RESULT_BAD_STATE;
    snprintf(out->build_id, sizeof out->build_id, "%.*s",
             (int)sizeof out->build_id - 1, desc.version);
    return WendyComResult_WENDY_COM_RESULT_OK;
}

WendyComResult hosted_companion_begin(size_t size)
{
    if (size == 0 || size > 4 * 1024 * 1024)
        return WendyComResult_WENDY_COM_RESULT_BAD_APP_SIZE;
    enum ota_protocol protocol = companion_ota_protocol();
    if (protocol == OTA_UNAVAILABLE || interrupted_legacy_update)
        return WendyComResult_WENDY_COM_RESULT_BAD_STATE;
    esp_err_t err = esp_hosted_slave_ota_begin();
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Could not begin companion OTA: %s", esp_err_to_name(err));
        return WendyComResult_WENDY_COM_RESULT_UNKNOWN_ERROR;
    }
    expected_size = size;
    written = 0;
    update_protocol = protocol;
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
    if (!hosted_companion_pending())
        return WendyComResult_WENDY_COM_RESULT_BAD_STATE;
    if (written != expected_size) {
        hosted_companion_abort();
        return WendyComResult_WENDY_COM_RESULT_BAD_APP_SIZE;
    }
    expected_size = 0;
    esp_err_t err = esp_hosted_slave_ota_end();
    if (err == ESP_OK && update_protocol != OTA_LEGACY)
        err = esp_hosted_slave_ota_activate();
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Could not finish companion OTA: %s", esp_err_to_name(err));
        return WendyComResult_WENDY_COM_RESULT_UNKNOWN_ERROR;
    }
    return WendyComResult_WENDY_COM_RESULT_OK;
}

void hosted_companion_abort(void)
{
    if (!hosted_companion_pending())
        return;
    expected_size = 0;
    if (update_protocol == OTA_LEGACY) {
        /* End also selects the boot partition on legacy firmware. A reboot
         * clears the abandoned handle without sending End on a partial image. */
        interrupted_legacy_update = true;
        return;
    }
    (void)esp_hosted_slave_ota_end();
}
