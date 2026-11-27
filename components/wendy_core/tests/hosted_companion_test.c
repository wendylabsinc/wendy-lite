#include <assert.h>
#include <string.h>

#include "esp_hosted_misc.h"
#include "esp_hosted_ota.h"
#include "hosted_companion.h"

static bool connected;
static uint32_t version;
static esp_err_t descriptor_result = ESP_OK, end_result = ESP_OK;
static unsigned descriptors, begins, writes, ends, activations;

bool wendy_hosted_peer_fw_version(uint32_t *out)
{
    *out = version;
    return connected;
}

esp_err_t esp_hosted_get_coprocessor_app_desc(esp_hosted_app_desc_t *desc)
{
    descriptors++;
    strcpy(desc->version, "wendy-aedc75c1bc026b3405b2a211");
    return descriptor_result;
}

esp_err_t esp_hosted_slave_ota_begin(void) { begins++; return ESP_OK; }
esp_err_t esp_hosted_slave_ota_write(uint8_t *data, uint32_t size)
{
    assert(data && size);
    writes++;
    return ESP_OK;
}
esp_err_t esp_hosted_slave_ota_end(void) { ends++; return end_result; }
esp_err_t esp_hosted_slave_ota_activate(void) { activations++; return ESP_OK; }

int main(void)
{
    const uint8_t image[] = {1, 2, 3};
    WendyComHostedCompanionInfo info = {0};
    assert(hosted_companion_get(&info) == WendyComResult_WENDY_COM_RESULT_BAD_STATE);
    assert(hosted_companion_begin(sizeof image) == WendyComResult_WENDY_COM_RESULT_BAD_STATE);
    assert(begins == 0 && descriptors == 0);

    connected = true;
    version = 0x020d01;
    descriptor_result = ESP_FAIL;
    assert(hosted_companion_get(&info) == WendyComResult_WENDY_COM_RESULT_BAD_STATE);
    descriptor_result = ESP_OK;
    assert(hosted_companion_get(&info) == WendyComResult_WENDY_COM_RESULT_OK);
    assert(strcmp(info.build_id, "wendy-aedc75c1bc026b3405b2a211") == 0);

    version = 0x020606;
    assert(hosted_companion_get(&info) == WendyComResult_WENDY_COM_RESULT_OK);
    assert(!info.build_id[0] && descriptors == 2);
    assert(hosted_companion_begin(sizeof image) == WendyComResult_WENDY_COM_RESULT_OK);
    assert(hosted_companion_write(1, image, 1) == WendyComResult_WENDY_COM_RESULT_BAD_APP_SIZE);
    assert(hosted_companion_write(0, image, 1) == WendyComResult_WENDY_COM_RESULT_OK);
    assert(hosted_companion_end() == WendyComResult_WENDY_COM_RESULT_BAD_APP_SIZE);
    assert(writes == 1 && ends == 1 && !activations && !hosted_companion_pending());

    version = 0x020d01;
    assert(hosted_companion_begin(sizeof image) == WendyComResult_WENDY_COM_RESULT_OK);
    assert(hosted_companion_write(0, image, sizeof image) == WendyComResult_WENDY_COM_RESULT_OK);
    end_result = ESP_FAIL;
    assert(hosted_companion_end() == WendyComResult_WENDY_COM_RESULT_UNKNOWN_ERROR);
    assert(ends == 2 && !activations);

    assert(hosted_companion_begin(sizeof image) == WendyComResult_WENDY_COM_RESULT_OK);
    assert(hosted_companion_write(0, image, sizeof image) == WendyComResult_WENDY_COM_RESULT_OK);
    end_result = ESP_OK;
    assert(hosted_companion_end() == WendyComResult_WENDY_COM_RESULT_OK);
    assert(ends == 3 && activations == 1);

    version = 0;  // Factory C6 advertises a valid transport without a version tag.
    assert(hosted_companion_get(&info) == WendyComResult_WENDY_COM_RESULT_OK);
    assert(!info.build_id[0] && descriptors == 2);
    assert(hosted_companion_begin(sizeof image) == WendyComResult_WENDY_COM_RESULT_OK);
    assert(hosted_companion_write(0, image, sizeof image) == WendyComResult_WENDY_COM_RESULT_OK);
    assert(hosted_companion_end() == WendyComResult_WENDY_COM_RESULT_OK);
    assert(ends == 4 && activations == 1);

    assert(hosted_companion_begin(sizeof image) == WendyComResult_WENDY_COM_RESULT_OK);
    assert(hosted_companion_write(0, image, 1) == WendyComResult_WENDY_COM_RESULT_OK);
    hosted_companion_abort();
    assert(ends == 4 && activations == 1 && !hosted_companion_pending());
    assert(hosted_companion_begin(sizeof image) == WendyComResult_WENDY_COM_RESULT_BAD_STATE);
    assert(begins == 5);
}
