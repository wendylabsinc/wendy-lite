#include <inttypes.h>
#include <stdbool.h>
#include <string.h>

#include "esp_log.h"
#include "esp_partition.h"
#include "pb_decode.h"

#include "wendy_conf.h"

#define TAG "wendy_conf"

#define MAGIC      "WYC0"
#define MAGIC_LEN  4
#define HEADER_LEN 8

#define WENDY_CONF_PART_SUBTYPE ((esp_partition_subtype_t)0x40)

static bool _capture_span(pb_istream_t *stream, const pb_field_t *field, void **arg)
{
    // For a pb_istream_from_buffer stream, state is the current read pointer,
    // so at callback entry it points to the first byte of the field content.
    struct wendy_conf_span *out = *arg;
    out->data = stream->state;
    out->size = stream->bytes_left;
    return pb_read(stream, NULL, stream->bytes_left);
}

static WendyConf                   s_conf               = WendyConf_init_zero;
static bool                        s_valid              = false;
static struct wendy_conf_span      s_device_name        = {NULL, 0};
static struct wendy_conf_span      s_network_ssid       = {NULL, 0};
static struct wendy_conf_span      s_network_password   = {NULL, 0};
static struct wendy_conf_span      s_cloud_host         = {NULL, 0};
static struct wendy_conf_span      s_key_der            = {NULL, 0};
static struct wendy_conf_span      s_cert_der           = {NULL, 0};
static struct wendy_conf_span      s_chain_der          = {NULL, 0};
static esp_partition_mmap_handle_t s_mmap;

void wendy_conf_init(void)
{
    const esp_partition_t *part = esp_partition_find_first(
        ESP_PARTITION_TYPE_DATA, WENDY_CONF_PART_SUBTYPE, "wendy_conf");
    if (!part) {
        ESP_LOGE(TAG, "partition not found");
        return;
    }

    const uint8_t *data;
    esp_partition_mmap_handle_t mmap;
    esp_err_t err = esp_partition_mmap(part, 0, part->size,
                                       ESP_PARTITION_MMAP_DATA,
                                       (const void **)&data, &mmap);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "mmap failed: %s", esp_err_to_name(err));
        return;
    }

    if (memcmp(data, MAGIC, MAGIC_LEN) != 0) {
        ESP_LOGE(TAG, "bad magic");
        esp_partition_munmap(mmap);
        return;
    }

    uint32_t pb_size = (uint32_t)data[4]
                     | ((uint32_t)data[5] << 8)
                     | ((uint32_t)data[6] << 16)
                     | ((uint32_t)data[7] << 24);

    if (pb_size == 0 || pb_size > part->size - HEADER_LEN) {
        ESP_LOGE(TAG, "invalid pb size %" PRIu32, pb_size);
        esp_partition_munmap(mmap);
        return;
    }

    s_device_name = (struct wendy_conf_span){NULL, 0};
    s_conf.device_name.funcs.decode = _capture_span;
    s_conf.device_name.arg = &s_device_name;

    s_network_ssid     = (struct wendy_conf_span){NULL, 0};
    s_network_password = (struct wendy_conf_span){NULL, 0};
    s_conf.wifi.networks[0].ssid.funcs.decode     = _capture_span;
    s_conf.wifi.networks[0].ssid.arg              = &s_network_ssid;
    s_conf.wifi.networks[0].password.funcs.decode = _capture_span;
    s_conf.wifi.networks[0].password.arg          = &s_network_password;

    s_cloud_host = (struct wendy_conf_span){NULL, 0};
    s_conf.provisioning.cloud_host.funcs.decode = _capture_span;
    s_conf.provisioning.cloud_host.arg          = &s_cloud_host;

    s_key_der   = (struct wendy_conf_span){NULL, 0};
    s_cert_der  = (struct wendy_conf_span){NULL, 0};
    s_chain_der = (struct wendy_conf_span){NULL, 0};
    s_conf.provisioning.key.funcs.decode   = _capture_span;
    s_conf.provisioning.key.arg            = &s_key_der;
    s_conf.provisioning.cert.funcs.decode  = _capture_span;
    s_conf.provisioning.cert.arg           = &s_cert_der;
    s_conf.provisioning.chain.funcs.decode = _capture_span;
    s_conf.provisioning.chain.arg          = &s_chain_der;

    pb_istream_t stream = pb_istream_from_buffer(data + HEADER_LEN, pb_size);
    bool ok = pb_decode_noinit(&stream, WendyConf_fields, &s_conf);

    if (!ok) {
        ESP_LOGE(TAG, "decode failed: %s", PB_GET_ERROR(&stream));
        esp_partition_munmap(mmap);
        s_conf             = (WendyConf)WendyConf_init_zero;
        s_device_name      = (struct wendy_conf_span){NULL, 0};
        s_network_ssid     = (struct wendy_conf_span){NULL, 0};
        s_network_password = (struct wendy_conf_span){NULL, 0};
        s_cloud_host       = (struct wendy_conf_span){NULL, 0};
        s_key_der          = (struct wendy_conf_span){NULL, 0};
        s_cert_der         = (struct wendy_conf_span){NULL, 0};
        s_chain_der        = (struct wendy_conf_span){NULL, 0};
        return;
    }

    s_mmap  = mmap; /* keep flash mapped — s_device_name.data points into it */
    s_valid = true;
    ESP_LOGI(TAG, "loaded %" PRIu32 " bytes", pb_size);
}

struct wendy_conf_span wendy_conf_get_device_name(void)
{
    return s_device_name;
}

struct wendy_conf_span wendy_conf_get_network_ssid(void)
{
    return s_network_ssid;
}

struct wendy_conf_span wendy_conf_get_network_password(void)
{
    return s_network_password;
}

int32_t wendy_conf_get_network_priority(void)
{
    return s_conf.wifi.networks[0].priority;
}

bool wendy_conf_get_network_hidden(void)
{
    return s_conf.wifi.networks[0].hidden;
}

WendyConfWifiSecurity wendy_conf_get_network_security(void)
{
    return s_conf.wifi.networks[0].security;
}

bool wendy_conf_get_enrolled(void)
{
    return s_conf.provisioning.enrolled;
}

int32_t wendy_conf_get_org_id(void)
{
    return s_conf.provisioning.org_id;
}

int32_t wendy_conf_get_asset_id(void)
{
    return s_conf.provisioning.asset_id;
}

struct wendy_conf_span wendy_conf_get_cloud_host(void)
{
    return s_cloud_host;
}

struct wendy_conf_span wendy_conf_get_private_key(void)
{
    return s_key_der;
}

struct wendy_conf_span wendy_conf_get_certificate(void)
{
    return s_cert_der;
}

struct wendy_conf_span wendy_conf_get_chain_of_trust(void)
{
    return s_chain_der;
}
