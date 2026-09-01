#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <stdio.h>

#include "esp_log.h"
#include "esp_mac.h"
#include "esp_partition.h"
#include "esp_system.h"
#include "pb_decode.h"

#include "wendy_conf.h"


//--- literals ---///

#define TAG "wendy_conf"

#define MAGIC      "WYC0"
#define MAGIC_LEN  4
#define HEADER_LEN 8

#define WENDY_CONF_PART_SUBTYPE ((esp_partition_subtype_t)0x40)

#define CONF_CACHE_INIT (struct conf_cache){ .conf = WendyConf_init_zero }


//--- types ---//

/**
 * The RAM-cached, decoded view of the flash conf.  The spans point into the
 * mmapped partition, so the mapping is kept for as long as the cache is valid.
 */
struct conf_cache {
    WendyConf                   conf;
    bool                        valid;
    const uint8_t              *pb_data; /* raw stored blob, in mmapped flash */
    size_t                      pb_size;
    esp_partition_mmap_handle_t mmap;
    struct wendy_conf_span      device_name;
    struct wendy_conf_span      network_ssid;
    struct wendy_conf_span      network_password;
    struct wendy_conf_span      cloud_host;
    struct wendy_conf_span      key_der;
    struct wendy_conf_span      cert_der;
    struct wendy_conf_span      chain_der;
};


//--- globals ---///

static struct conf_cache s_cache = CONF_CACHE_INIT;

/* 12 hex digits plus the terminator. Empty until built. */
static char s_device_id[13];


//--- functions ---//

static void _build_device_id(void)
{
    uint8_t mac[6];
    esp_err_t err = esp_read_mac(mac, ESP_MAC_EFUSE_FACTORY);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_read_mac failed: %s", esp_err_to_name(err));
        return;
    }
    snprintf(s_device_id, sizeof(s_device_id), "%02x%02x%02x%02x%02x%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

const char *wendy_conf_get_device_id(void)
{
    // Built during wendy_conf_init(), and derived from hardware rather than
    // the conf blob, so a missing or corrupt conf does not explain an empty
    // one here.  Rather than hand back an empty string a caller has no way to
    // notice, fail loudly.
    if (!s_device_id[0])
        esp_system_abort("device id unavailable (wendy_conf_init not run?)");
    return s_device_id;
}

static bool _capture_span(pb_istream_t *stream, const pb_field_t *field, void **arg)
{
    // For a pb_istream_from_buffer stream, state is the current read pointer,
    // so at callback entry it points to the first byte of the field content.
    struct wendy_conf_span *out = *arg;
    out->data = stream->state;
    out->size = stream->bytes_left;
    return pb_read(stream, NULL, stream->bytes_left);
}

/**
 * Reset the cache so no getter can return data from a conf that is being
 * overwritten.  Getters return empty spans / zero scalars afterwards.
 */
static void _invalidate_cache(void)
{
    if (s_cache.valid)
        esp_partition_munmap(s_cache.mmap);
    s_cache = CONF_CACHE_INIT;
}

void wendy_conf_init(void)
{
    // Before any of the early returns below: the device ID does not come from
    // the partition, so a missing or corrupt conf must not cost us one.
    _build_device_id();

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

    s_cache = (struct conf_cache)CONF_CACHE_INIT;

    s_cache.conf.device_name.funcs.decode = _capture_span;
    s_cache.conf.device_name.arg          = &s_cache.device_name;

    s_cache.conf.wifi.networks[0].ssid.funcs.decode     = _capture_span;
    s_cache.conf.wifi.networks[0].ssid.arg              = &s_cache.network_ssid;
    s_cache.conf.wifi.networks[0].password.funcs.decode = _capture_span;
    s_cache.conf.wifi.networks[0].password.arg          = &s_cache.network_password;

    s_cache.conf.provisioning.cloud_host.funcs.decode = _capture_span;
    s_cache.conf.provisioning.cloud_host.arg          = &s_cache.cloud_host;

    s_cache.conf.provisioning.key.funcs.decode   = _capture_span;
    s_cache.conf.provisioning.key.arg            = &s_cache.key_der;
    s_cache.conf.provisioning.cert.funcs.decode  = _capture_span;
    s_cache.conf.provisioning.cert.arg           = &s_cache.cert_der;
    s_cache.conf.provisioning.chain.funcs.decode = _capture_span;
    s_cache.conf.provisioning.chain.arg          = &s_cache.chain_der;

    pb_istream_t stream = pb_istream_from_buffer(data + HEADER_LEN, pb_size);
    bool ok = pb_decode_noinit(&stream, WendyConf_fields, &s_cache.conf);

    if (!ok) {
        ESP_LOGE(TAG, "decode failed: %s", PB_GET_ERROR(&stream));
        esp_partition_munmap(mmap);
        s_cache = (struct conf_cache)CONF_CACHE_INIT;
        return;
    }

    s_cache.mmap    = mmap; /* keep flash mapped — the spans point into it */
    s_cache.pb_data = data + HEADER_LEN;
    s_cache.pb_size = pb_size;
    s_cache.valid   = true;
    ESP_LOGI(TAG, "loaded %" PRIu32 " bytes", pb_size);
}

/**
 * Scan the top-level fields of a protobuf-encoded message and return a bitmask
 * of the field numbers present (bit N set = field number N present; field
 * numbers >= 32 are ignored, WendyConf root fields are 1..3).
 */
static bool _scan_root_fields(const uint8_t *data, size_t size, uint32_t *mask)
{
    pb_istream_t stream = pb_istream_from_buffer(data, size);
    *mask = 0;
    while (stream.bytes_left > 0) {
        pb_wire_type_t wire_type;
        uint32_t       tag;
        bool           eof;
        if (!pb_decode_tag(&stream, &wire_type, &tag, &eof)) {
            if (eof)
                break;
            return false;
        }
        if (tag < 32)
            *mask |= 1u << tag;
        if (!pb_skip_field(&stream, wire_type))
            return false;
    }
    return true;
}

/**
 * Copy into out the raw bytes of every top-level field of in_data whose
 * field number is present in mask (bit N set = keep field number N), and
 * store the total size in out_size.  Pass out == NULL for a dry run that
 * only computes the size.
 */
static bool _copy_kept_fields(const uint8_t *in_data, size_t in_size,
                              uint32_t mask, uint8_t *out, size_t *out_size)
{
    size_t       pos    = 0;
    pb_istream_t stream = pb_istream_from_buffer(in_data, in_size);
    while (stream.bytes_left > 0) {
        // For a pb_istream_from_buffer stream, state is the current read
        // pointer, which lets us recover the raw bytes of each field.
        size_t         start = (const uint8_t *)stream.state - in_data;
        pb_wire_type_t wire_type;
        uint32_t       tag;
        bool           eof;
        if (!pb_decode_tag(&stream, &wire_type, &tag, &eof)) {
            if (eof)
                break;
            return false;
        }
        if (!pb_skip_field(&stream, wire_type))
            return false;
        size_t end = (const uint8_t *)stream.state - in_data;
        if (tag < 32 && (mask & (1u << tag))) {
            if (out)
                memcpy(out + pos, in_data + start, end - start);
            pos += end - start;
        }
    }

    *out_size = pos;
    return true;
}

esp_err_t wendy_conf_write(const void *pb_data, size_t pb_size, enum wendy_conf_write_mode mode)
{
    if (!pb_data || pb_size == 0)
        return ESP_ERR_INVALID_ARG;

    // Validate that the blob decodes as a WendyConf message.  Callback fields
    // with no decode function are simply skipped, so no callbacks are needed.
    WendyConf    tmp    = WendyConf_init_zero;
    pb_istream_t stream = pb_istream_from_buffer(pb_data, pb_size);
    if (!pb_decode(&stream, WendyConf_fields, &tmp)) {
        ESP_LOGE(TAG, "invalid conf: %s", PB_GET_ERROR(&stream));
        return ESP_ERR_INVALID_ARG;
    }

    const esp_partition_t *part = esp_partition_find_first(
        ESP_PARTITION_TYPE_DATA, WENDY_CONF_PART_SUBTYPE, "wendy_conf");
    if (!part) {
        ESP_LOGE(TAG, "partition not found");
        return ESP_ERR_NOT_FOUND;
    }

    uint32_t keep_mask = 0;
    size_t   kept_size = 0;
    uint8_t *kept      = NULL;

    if (mode == WENDY_CONF_WRITE_MODE_UPDATE && s_cache.valid) {
        // Keep the stored fields the new conf does not provide.  Dry run:
        // compute their size, so the buffer below can be allocated exactly.
        uint32_t present;
        if (!_scan_root_fields(pb_data, pb_size, &present) ||
            !_copy_kept_fields(s_cache.pb_data, s_cache.pb_size, ~present,
                               NULL, &kept_size)) {
            ESP_LOGE(TAG, "merge failed");
            return ESP_ERR_INVALID_STATE;
        }
        keep_mask = ~present;
    }

    size_t final_size = kept_size + pb_size;
    if (HEADER_LEN + final_size > part->size) {
        ESP_LOGE(TAG, "conf too large: %zu bytes", final_size);
        return ESP_ERR_INVALID_SIZE;
    }

    if (kept_size > 0) {
        // The kept fields must move to RAM: they live in mmapped flash,
        // which becomes invalid once the partition is erased.
        kept = malloc(kept_size);
        if (!kept)
            return ESP_ERR_NO_MEM;
        _copy_kept_fields(s_cache.pb_data, s_cache.pb_size, keep_mask,
                          kept, &kept_size);
    }

    // The stored conf is about to be destroyed; make sure no getter can
    // return a view into it, even if the erase or write fails below.
    _invalidate_cache();

    esp_err_t err;

    size_t erase_size = (HEADER_LEN + final_size + part->erase_size - 1)
                      / part->erase_size * part->erase_size;
    err = esp_partition_erase_range(part, 0, erase_size);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "erase failed: %s", esp_err_to_name(err));
        goto out;
    }

    uint8_t header[HEADER_LEN] = {
        MAGIC[0], MAGIC[1], MAGIC[2], MAGIC[3],
        (uint8_t)final_size,
        (uint8_t)(final_size >> 8),
        (uint8_t)(final_size >> 16),
        (uint8_t)(final_size >> 24),
    };
    err = esp_partition_write(part, 0, header, HEADER_LEN);
    if (err == ESP_OK && kept_size > 0)
        err = esp_partition_write(part, HEADER_LEN, kept, kept_size);
    if (err == ESP_OK)
        err = esp_partition_write(part, HEADER_LEN + kept_size, pb_data, pb_size);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "write failed: %s", esp_err_to_name(err));
        goto out;
    }

    ESP_LOGI(TAG, "wrote %zu bytes", final_size);

out:
    free(kept);
    return err;
}

size_t wendy_conf_get_max_size(void)
{
    const esp_partition_t *part = esp_partition_find_first(
        ESP_PARTITION_TYPE_DATA, WENDY_CONF_PART_SUBTYPE, "wendy_conf");
    if (!part) {
        ESP_LOGE(TAG, "partition not found");
        return 0;
    }
    return part->size - HEADER_LEN;
}

struct wendy_conf_span wendy_conf_get_device_name(void)
{
    return s_cache.device_name;
}

struct wendy_conf_span wendy_conf_get_network_ssid(void)
{
    return s_cache.network_ssid;
}

struct wendy_conf_span wendy_conf_get_network_password(void)
{
    return s_cache.network_password;
}

int32_t wendy_conf_get_network_priority(void)
{
    return s_cache.conf.wifi.networks[0].priority;
}

bool wendy_conf_get_network_hidden(void)
{
    return s_cache.conf.wifi.networks[0].hidden;
}

WendyConfWifiSecurity wendy_conf_get_network_security(void)
{
    return s_cache.conf.wifi.networks[0].security;
}

bool wendy_conf_get_enrolled(void)
{
    return s_cache.conf.provisioning.enrolled;
}

int32_t wendy_conf_get_org_id(void)
{
    return s_cache.conf.provisioning.org_id;
}

int32_t wendy_conf_get_asset_id(void)
{
    return s_cache.conf.provisioning.asset_id;
}

struct wendy_conf_span wendy_conf_get_cloud_host(void)
{
    return s_cache.cloud_host;
}

struct wendy_conf_span wendy_conf_get_private_key(void)
{
    return s_cache.key_der;
}

struct wendy_conf_span wendy_conf_get_certificate(void)
{
    return s_cache.cert_der;
}

struct wendy_conf_span wendy_conf_get_chain_of_trust(void)
{
    return s_cache.chain_der;
}

extern const uint8_t default_cert_der_start[] asm("_binary_default_cert_der_start");
extern const uint8_t default_cert_der_end[]   asm("_binary_default_cert_der_end");
extern const uint8_t default_key_der_start[]  asm("_binary_default_key_der_start");
extern const uint8_t default_key_der_end[]    asm("_binary_default_key_der_end");

bool wendy_conf_is_provisioned(void)
{
    return s_cache.key_der.size > 0
        && s_cache.cert_der.size > 0
        && s_cache.chain_der.size > 0;
}

struct wendy_conf_span wendy_conf_get_default_certificate(void)
{
    return (struct wendy_conf_span){
        .data = default_cert_der_start,
        .size = (size_t)(default_cert_der_end - default_cert_der_start),
    };
}

struct wendy_conf_span wendy_conf_get_default_private_key(void)
{
    return (struct wendy_conf_span){
        .data = default_key_der_start,
        .size = (size_t)(default_key_der_end - default_key_der_start),
    };
}

void wendy_conf_copy_span(char *dest, size_t dest_size, struct wendy_conf_span src)
{
    if (src.size == 0 || !src.data) {
        if (dest_size > 0)
            dest[0] = '\0';
        return;
    }
    size_t copy_size = src.size < dest_size - 1 ? src.size : dest_size - 1;
    memcpy(dest, src.data, copy_size);
    dest[copy_size] = '\0';
}
