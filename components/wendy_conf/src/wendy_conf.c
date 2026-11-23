#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <stdio.h>
#include <pthread.h>

#include "esp_log.h"
#include "esp_mac.h"
#include "esp_partition.h"
#include "esp_system.h"
#include "nvs.h"
#include "pb_decode.h"

#include "wendy_conf.h"
#include "wendy_cert_bundle.h"
#include <psa/crypto.h>

//--- literals ---///

#define TAG "wendy_conf"

#define MAGIC      "WYC0"
#define MAGIC_LEN  4
#define HEADER_LEN 8
#define RECOVERY_MAGIC "WCR1"
/* The removed imported-credential field remains reserved on the wire. */
#define RETIRED_ENROLLMENT_TAG 3

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
    struct wendy_conf_span      enrollment_time;
    struct wendy_conf_span      device_roots, tsa_roots, https_roots, lite_device_intermediates;
};


//--- globals ---///

static pthread_mutex_t s_cache_lock = PTHREAD_MUTEX_INITIALIZER;
static struct conf_cache s_cache = CONF_CACHE_INIT;
static uint64_t s_generation = 1;
/* Keep authentication required while configuration is replaced or unreadable.
 * Only a completed enrollment reset may clear this during the current boot. */
static bool s_enrollment_required;

/* 12 hex digits plus the terminator. Empty until built. */
static char s_device_id[13];

/* The configured name, or the fallback built from the device ID. Empty until
 * built. */
static char s_resolved_device_name[CONFIG_WENDY_DEVICE_NAME_BUF_SIZE];

/* How many trailing device-ID hex digits the fallback name carries. */
#define FALLBACK_ID_DIGITS 4


//--- functions ---//

static bool _scan_root_fields(const uint8_t *data, size_t size, uint32_t *mask);
static esp_err_t write_mesh_trust(const uint8_t *data, size_t size);
static esp_err_t clear_mesh_trust_locked(void);

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

/**
 * Resolve the name every transport advertises.  Called exactly once, from
 * wendy_conf_init() once the conf cache is settled: the name is fixed for the
 * life of the boot, so every subsystem that asks gets the same answer.  The
 * copy below is what makes that possible — it lifts the name out of the
 * mmapped partition, which a later write unmaps and erases.
 */
static void _build_resolved_device_name(void)
{
    // The configured name first: a named board keeps its name even if the MAC
    // read failed, in which case the device ID getter below would abort.
    wendy_conf_copy_span(s_resolved_device_name, sizeof(s_resolved_device_name),
                         s_cache.device_name);
    if (s_resolved_device_name[0])
        return;

    // Unnamed: fall back to the tail of the device ID.  Not the head — that is
    // the vendor OUI, the same on every board we ship.
    const char *id     = wendy_conf_get_device_id();
    size_t      id_len = strlen(id);
    const char *tail   = id_len > FALLBACK_ID_DIGITS
                       ? id + id_len - FALLBACK_ID_DIGITS
                       : id;
    snprintf(s_resolved_device_name, sizeof(s_resolved_device_name), "%s-%s",
             CONFIG_WENDY_DEVICE_NAME_DEFAULT_PREFIX, tail);
}

const char *wendy_conf_get_resolved_device_name(void)
{
    return s_resolved_device_name;
}

const char *wendy_conf_get_resolved_device_display_name(void)
{
    return wendy_conf_get_resolved_device_name();
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
static void advance_generation(void)
{
    if (s_generation == UINT64_MAX)
        esp_system_abort("configuration generation exhausted");
    s_generation++;
}

static void _invalidate_cache(void)
{
    advance_generation();
    if (s_cache.valid)
        esp_partition_munmap(s_cache.mmap);
    s_cache = CONF_CACHE_INIT;
}

/**
 * Map the conf partition and decode it into the cache.  Every failure leaves
 * the cache invalid, which the getters report as empty spans / zero scalars.
 */
static void _load_conf(void)
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

    if (pb_size > part->size - HEADER_LEN) {
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

    s_cache.conf.enrollment.signed_time.funcs.decode = _capture_span;
    s_cache.conf.enrollment.signed_time.arg = &s_cache.enrollment_time;
    s_cache.conf.enrollment.device_roots.funcs.decode = _capture_span;
    s_cache.conf.enrollment.device_roots.arg = &s_cache.device_roots;
    s_cache.conf.enrollment.tsa_roots.funcs.decode = _capture_span;
    s_cache.conf.enrollment.tsa_roots.arg = &s_cache.tsa_roots;
    s_cache.conf.enrollment.https_roots.funcs.decode = _capture_span;
    s_cache.conf.enrollment.https_roots.arg = &s_cache.https_roots;
    s_cache.conf.enrollment.lite_device_intermediates =
        (pb_callback_t){.funcs.decode = _capture_span, .arg = &s_cache.lite_device_intermediates};
    pb_istream_t stream = pb_istream_from_buffer(data + HEADER_LEN, pb_size);
    uint32_t fields;
    bool ok = pb_decode_noinit(&stream, WendyConf_fields, &s_cache.conf) &&
              _scan_root_fields(data + HEADER_LEN, pb_size, &fields);

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
    bool retired = (fields & (1u << RETIRED_ENROLLMENT_TAG)) != 0;
    s_enrollment_required |= s_cache.conf.has_enrollment || retired;
    if (retired && !s_cache.conf.has_enrollment)
        ESP_LOGW(TAG, "Retired credentials require enrollment or reset over USB");
    ESP_LOGI(TAG, "loaded %" PRIu32 " bytes", pb_size);
}

void wendy_conf_init(void)
{
    // The device ID does not come from the partition, so a missing or corrupt
    // conf must not cost us one — nor the name we derive from it.
    _build_device_id();
    _load_conf();
    _build_resolved_device_name();
}

/**
 * Scan the top-level fields of a protobuf-encoded message and return a bitmask
 * of the field numbers present (bit N set = field number N present; field
 * numbers >= 32 are ignored, WendyConf root fields are 1..4).
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
 * field number is present in mask (bit N set = keep field number N). Fields
 * numbered 32 or above are kept only when keep_unknown is true. Store the
 * total size in out_size. Pass out == NULL for a dry run that computes size.
 */
static bool _copy_kept_fields(const uint8_t *in_data, size_t in_size,
                              uint32_t mask, bool keep_unknown,
                              uint8_t *out, size_t *out_size)
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
        if (tag < 32 ? (mask & (1u << tag)) != 0 : keep_unknown) {
            if (out)
                memcpy(out + pos, in_data + start, end - start);
            pos += end - start;
        }
    }

    *out_size = pos;
    return true;
}

static esp_err_t _write_conf(const void *pb_data, size_t pb_size, enum wendy_conf_write_mode mode)
{
    if (!pb_data)
        return ESP_ERR_INVALID_ARG;

    uint32_t fields;
    if (!_scan_root_fields(pb_data, pb_size, &fields))
        return ESP_ERR_INVALID_ARG;
    if (fields & (1u << RETIRED_ENROLLMENT_TAG)) {
        ESP_LOGE(TAG, "Imported credentials are unsupported; enroll over USB");
        return ESP_ERR_INVALID_ARG;
    }

    // Check enrollment sizes and authorization before replacing persisted data.
    WendyConf tmp = WendyConf_init_zero;
    struct wendy_conf_span spans[5] = {0};
    tmp.enrollment.signed_time = (pb_callback_t){.funcs.decode = _capture_span, .arg = &spans[0]};
    tmp.enrollment.device_roots = (pb_callback_t){.funcs.decode = _capture_span, .arg = &spans[1]};
    tmp.enrollment.tsa_roots = (pb_callback_t){.funcs.decode = _capture_span, .arg = &spans[2]};
    tmp.enrollment.https_roots = (pb_callback_t){.funcs.decode = _capture_span, .arg = &spans[3]};
    tmp.enrollment.lite_device_intermediates =
        (pb_callback_t){.funcs.decode = _capture_span, .arg = &spans[4]};
    pb_istream_t stream = pb_istream_from_buffer(pb_data, pb_size);
    if (!pb_decode_noinit(&stream, WendyConf_fields, &tmp)) {
        ESP_LOGE(TAG, "invalid conf: %s", PB_GET_ERROR(&stream));
        return ESP_ERR_INVALID_ARG;
    }

    size_t enrollment_size = 0;
    for (size_t i = 0; i < 5; i++) {
        size_t limit = (i == 1 || i == 4) ? WENDY_CONF_MAX_DEVICE_TRUST_BUNDLE
                             : i ? WENDY_CONF_MAX_TRUST_BUNDLE : WENDY_CONF_MAX_ENROLLMENT_DATA;
        if (spans[i].size > limit ||
            spans[i].size > WENDY_CONF_MAX_ENROLLMENT_DATA - enrollment_size)
            return ESP_ERR_INVALID_SIZE;
        enrollment_size += spans[i].size;
        bool optional_tsa = i == 2 && !strcmp(tmp.enrollment.time_url, "roughtime") && !spans[i].size;
        if (spans[i].size && i && !tmp.enrollment.provision_trust)
            return ESP_ERR_INVALID_ARG;
        if (i && i < 4 && !optional_tsa && tmp.enrollment.provision_trust && !spans[i].size)
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
            !_copy_kept_fields(s_cache.pb_data, s_cache.pb_size, ~present, false,
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
        _copy_kept_fields(s_cache.pb_data, s_cache.pb_size, keep_mask, false,
                          kept, &kept_size);
    }

    // The stored conf is about to be destroyed; make sure no getter can
    // return a view into it, even if the erase or write fails below.
    s_enrollment_required |= tmp.has_enrollment;
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
    if (err == ESP_OK && pb_size > 0)
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

extern const uint8_t default_cert_der_start[] asm("_binary_default_cert_der_start");
extern const uint8_t default_cert_der_end[]   asm("_binary_default_cert_der_end");
extern const uint8_t default_key_der_start[]  asm("_binary_default_key_der_start");
extern const uint8_t default_key_der_end[]    asm("_binary_default_key_der_end");

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

esp_err_t wendy_conf_write(const void *data, size_t size, enum wendy_conf_write_mode mode)
{
    if (!data || size == 0)
        return ESP_ERR_INVALID_ARG;
    if (mode == WENDY_CONF_WRITE_MODE_MESH_TRUST)
        return write_mesh_trust(data, size);
    bool wifi_only = mode == WENDY_CONF_WRITE_MODE_WIFI_ONLY;
    if (wifi_only) {
        pb_istream_t input = pb_istream_from_buffer(data, size);
        bool seen = false;
        while (input.bytes_left) {
            pb_wire_type_t wire;
            uint32_t tag;
            bool eof;
            if (!pb_decode_tag(&input, &wire, &tag, &eof) ||
                tag != WendyConf_wifi_tag || wire != PB_WT_STRING || seen ||
                !pb_skip_field(&input, wire))
                return ESP_ERR_INVALID_ARG;
            seen = true;
        }
        if (!seen) return ESP_ERR_INVALID_ARG;
        mode = WENDY_CONF_WRITE_MODE_UPDATE;
    }
    pthread_mutex_lock(&s_cache_lock);
    esp_err_t result = wifi_only && s_enrollment_required && !s_cache.valid
        ? ESP_ERR_INVALID_STATE : _write_conf(data, size, mode);
    pthread_mutex_unlock(&s_cache_lock);
    return result;
}

esp_err_t wendy_conf_clear_enrollment(void)
{
    esp_err_t result = ESP_ERR_INVALID_STATE;
    uint8_t *journal = NULL;
    nvs_handle_t recovery;
    bool opened = false;
    pthread_mutex_lock(&s_cache_lock);

    // The PKI reset caller initializes this partition and commits its reset
    // marker before calling us. Keep recovery data outside the identity namespace.
    result = nvs_open_from_partition("wendy_pki", "conf_recovery", NVS_READWRITE, &recovery);
    if (result != ESP_OK)
        goto done;
    opened = true;
    const uint32_t keep_mask = ~((1u << RETIRED_ENROLLMENT_TAG) |
                                 (1u << WendyConf_enrollment_tag));
    size_t journal_size = 0, kept_size = 0;
    result = nvs_get_blob(recovery, "retained", NULL, &journal_size);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        // A previous upload may have invalidated the cache. An unreadable
        // configuration without a journal cannot be recovered safely.
        if (!s_cache.valid)
            _load_conf();
        result = ESP_ERR_INVALID_STATE;
        if (!s_cache.valid ||
            !_copy_kept_fields(s_cache.pb_data, s_cache.pb_size, keep_mask, true,
                               NULL, &kept_size))
            goto done;
        if (kept_size == s_cache.pb_size) {
            result = ESP_OK;
            goto done;
        }

        // The prefix makes an empty retained config a nonempty, versioned blob.
        journal_size = MAGIC_LEN + kept_size;
        journal = malloc(journal_size);
        if (!journal) {
            result = ESP_ERR_NO_MEM;
            goto done;
        }
        memcpy(journal, RECOVERY_MAGIC, MAGIC_LEN);
        if (!_copy_kept_fields(s_cache.pb_data, s_cache.pb_size, keep_mask, true,
                               journal + MAGIC_LEN, &kept_size))
            goto done;
        result = nvs_set_blob(recovery, "retained", journal, journal_size);
        if (result == ESP_OK)
            result = nvs_commit(recovery);
        if (result != ESP_OK)
            goto done;
    } else if (result == ESP_OK) {
        // A committed journal is authoritative even if an interrupted flash
        // write left a decodable, but incomplete, configuration behind.
        result = ESP_ERR_INVALID_SIZE;
        if (journal_size < MAGIC_LEN || journal_size - MAGIC_LEN > wendy_conf_get_max_size())
            goto done;
        journal = malloc(journal_size);
        if (!journal) {
            result = ESP_ERR_NO_MEM;
            goto done;
        }
        size_t expected_size = journal_size;
        result = nvs_get_blob(recovery, "retained", journal, &journal_size);
        if (result != ESP_OK)
            goto done;
        result = ESP_ERR_INVALID_STATE;
        if (journal_size != expected_size || memcmp(journal, RECOVERY_MAGIC, MAGIC_LEN) ||
            !_copy_kept_fields(journal + MAGIC_LEN, journal_size - MAGIC_LEN,
                               keep_mask, true, NULL, &kept_size) ||
            kept_size != journal_size - MAGIC_LEN)
            goto done;
    } else {
        goto done;
    }

    // Refresh from flash even when the cache is valid. Verify exact bytes before
    // dropping the only durable copy of fields retained through a failed write.
    _invalidate_cache();
    _load_conf();
    if (!s_cache.valid || s_cache.pb_size != kept_size ||
        memcmp(s_cache.pb_data, journal + MAGIC_LEN, kept_size)) {
        result = _write_conf(journal + MAGIC_LEN, kept_size, WENDY_CONF_WRITE_MODE_REPLACE);
        if (result != ESP_OK)
            goto done;
        _load_conf();
        if (!s_cache.valid || s_cache.pb_size != kept_size ||
            memcmp(s_cache.pb_data, journal + MAGIC_LEN, kept_size)) {
            result = ESP_ERR_INVALID_STATE;
            goto done;
        }
    }
    result = nvs_erase_key(recovery, "retained");
    if (result == ESP_ERR_NVS_NOT_FOUND)
        result = ESP_OK;
    if (result == ESP_OK)
        result = nvs_commit(recovery);

done:
    if (opened)
        nvs_close(recovery);
    free(journal);
    if (result == ESP_OK)
        result = clear_mesh_trust_locked();
    if (result == ESP_OK)
        s_enrollment_required = false;
    pthread_mutex_unlock(&s_cache_lock);
    return result;
}

enum enrollment_selection {
    ENROLLMENT_TIME = 1U << 0,
    ENROLLMENT_DEVICE_ROOTS = 1U << 1,
    ENROLLMENT_TSA_ROOTS = 1U << 2,
    ENROLLMENT_HTTPS_ROOTS = 1U << 3,
    ENROLLMENT_ALL = (1U << 4) - 1,
    ENROLLMENT_LITE_INTERMEDIATES = 1U << 4,
    ENROLLMENT_USE_MESH_TRUST = 1U << 5,
};

/* Store the DER bundle as one NVS record, bound to the enrolled tenant and
 * device. The original provisioning trust remains available for issuance. */
struct mesh_trust_record {
    char tenant[37], device[37];
    uint8_t der[];
};

static const char *const mesh_trust_keys[] = {"roots", "issuers"};

/* The caller holds s_cache_lock. Reset completion includes the overlays even
 * if the retained configuration was already committed by an earlier attempt. */
static esp_err_t clear_mesh_trust_locked(void)
{
    nvs_handle_t h;
    esp_err_t status = nvs_open_from_partition("wendy_pki", "mesh_trust", NVS_READONLY, &h);
    if (status == ESP_ERR_NVS_NOT_FOUND)
        return ESP_OK;
    if (status != ESP_OK)
        return status;
    nvs_close(h);
    status = nvs_open_from_partition("wendy_pki", "mesh_trust", NVS_READWRITE, &h);
    if (status != ESP_OK)
        return status;
    for (size_t i = 0; i < sizeof mesh_trust_keys / sizeof mesh_trust_keys[0]; i++) {
        status = nvs_erase_key(h, mesh_trust_keys[i]);
        if (status != ESP_OK && status != ESP_ERR_NVS_NOT_FOUND)
            break;
    }
    if (status == ESP_OK || status == ESP_ERR_NVS_NOT_FOUND)
        status = nvs_commit(h);
    nvs_close(h);
    return status;
}

static esp_err_t read_mesh_trust(bool intermediates, struct mesh_trust_record **record, size_t *size)
{
    *record = NULL;
    *size = 0;
    nvs_handle_t h;
    esp_err_t status = nvs_open_from_partition("wendy_pki", "mesh_trust", NVS_READONLY, &h);
    if (status == ESP_ERR_NVS_NOT_FOUND || status == ESP_ERR_NVS_PART_NOT_FOUND ||
        status == ESP_ERR_NVS_NOT_INITIALIZED)
        return ESP_OK;
    if (status != ESP_OK)
        return status;
    size_t bytes = 0;
    const char *name = mesh_trust_keys[intermediates];
    status = nvs_get_blob(h, name, NULL, &bytes);
    if (status == ESP_ERR_NVS_NOT_FOUND) {
        status = ESP_OK;
    } else if (status == ESP_OK) {
        if (bytes <= sizeof **record || bytes - sizeof **record > WENDY_CONF_MAX_DEVICE_TRUST_BUNDLE) {
            status = ESP_ERR_INVALID_SIZE;
        } else {
            struct mesh_trust_record *stored = malloc(bytes);
            status = stored ? nvs_get_blob(h, name, stored, &bytes) : ESP_ERR_NO_MEM;
            if (status == ESP_OK && bytes > sizeof *stored &&
                !strncmp(stored->tenant, s_cache.conf.enrollment.tenant_id, sizeof stored->tenant) &&
                !strncmp(stored->device, s_cache.conf.enrollment.device_id, sizeof stored->device)) {
                *record = stored;
                *size = bytes - sizeof *stored;
            } else {
                free(stored);
            }
        }
    }
    nvs_close(h);
    return status;
}

esp_err_t wendy_conf_store_mesh_trust(uint64_t generation, bool intermediates,
                                    const uint8_t *der, size_t size)
{
    if (!der || !size || size > WENDY_CONF_MAX_DEVICE_TRUST_BUNDLE)
        return ESP_ERR_INVALID_ARG;
    pthread_mutex_lock(&s_cache_lock);
    esp_err_t result = ESP_ERR_INVALID_STATE;
    struct mesh_trust_record *record = NULL;
    size_t previous_size;
    if (!s_cache.valid || !s_cache.conf.has_enrollment || generation != s_generation)
        goto done;
    result = read_mesh_trust(intermediates, &record, &previous_size);
    if (result != ESP_OK || (record && previous_size == size && !memcmp(record->der, der, size)))
        goto done;
    free(record);
    record = calloc(1, sizeof *record + size);
    if (!record) {
        result = ESP_ERR_NO_MEM;
        goto done;
    }
    memcpy(record->tenant, s_cache.conf.enrollment.tenant_id, 36);
    memcpy(record->device, s_cache.conf.enrollment.device_id, 36);
    memcpy(record->der, der, size);
    nvs_handle_t h;
    result = nvs_open_from_partition("wendy_pki", "mesh_trust", NVS_READWRITE, &h);
    if (result == ESP_OK) {
        result = nvs_set_blob(h, mesh_trust_keys[intermediates], record, sizeof *record + size);
        if (result == ESP_OK)
            result = nvs_commit(h);
        nvs_close(h);
    }
    if (result == ESP_OK)
        advance_generation();
done:
    free(record);
    pthread_mutex_unlock(&s_cache_lock);
    return result;
}

static esp_err_t write_mesh_trust(const uint8_t *data, size_t size)
{
    uint32_t fields = 0;
    if (!_scan_root_fields(data, size, &fields) || fields != (1u << WendyConf_enrollment_tag))
        return ESP_ERR_INVALID_ARG;
    WendyConf payload = WendyConf_init_zero;
    struct wendy_conf_span roots = {0}, issuers = {0};
    payload.enrollment.device_roots = (pb_callback_t){.funcs.decode = _capture_span, .arg = &roots};
    payload.enrollment.lite_device_intermediates = (pb_callback_t){.funcs.decode = _capture_span, .arg = &issuers};
    pb_istream_t stream = pb_istream_from_buffer(data, size);
    if (!pb_decode_noinit(&stream, WendyConf_fields, &payload) || !payload.has_enrollment ||
        strlen(payload.enrollment.tenant_id) != 36 || strlen(payload.enrollment.device_id) != 36 ||
        (!!roots.size == !!issuers.size))
        return ESP_ERR_INVALID_ARG;
    struct wendy_conf_span trust = roots.size ? roots : issuers;
    size_t der_size = 0;
    if (trust.size > WENDY_CONF_MAX_DEVICE_TRUST_BUNDLE ||
        wendy_cert_bundle_measure(trust.data, trust.size, &der_size) || der_size != trust.size)
        return ESP_ERR_INVALID_ARG;
    pthread_mutex_lock(&s_cache_lock);
    uint64_t generation = s_cache.valid && s_cache.conf.has_enrollment &&
        !strcmp(payload.enrollment.tenant_id, s_cache.conf.enrollment.tenant_id) &&
        !strcmp(payload.enrollment.device_id, s_cache.conf.enrollment.device_id)
        ? s_generation : 0;
    pthread_mutex_unlock(&s_cache_lock);
    return wendy_conf_store_mesh_trust(generation, issuers.size != 0, trust.data, trust.size);
}

static esp_err_t copy_enrollment(WendyConfEnrollment *config,
                                 struct wendy_conf_enrollment_data *data, unsigned selection,
                                 bool der)
{
    if (!config || !data)
        return ESP_ERR_INVALID_ARG;
    esp_err_t result = ESP_ERR_INVALID_STATE;
    struct mesh_trust_record *mesh_roots = NULL, *mesh_issuers = NULL;
    memset(config, 0, sizeof *config);
    memset(data, 0, sizeof *data);
    pthread_mutex_lock(&s_cache_lock);
    if (s_cache.valid && s_cache.conf.has_enrollment) {
        struct wendy_conf_span spans[] = {s_cache.enrollment_time, s_cache.device_roots,
                                         s_cache.tsa_roots, s_cache.https_roots,
                                         s_cache.lite_device_intermediates};
        struct wendy_conf_span *copies[] = {&data->signed_time, &data->device_roots,
                                          &data->tsa_roots, &data->https_roots,
                                          &data->lite_device_intermediates};
        /* Partial snapshots must not hide forbidden runtime trust in another
         * domain. The encoded API keeps its existing import policy. */
        if (der && !s_cache.conf.enrollment.provision_trust &&
            (spans[1].size || spans[2].size || spans[3].size || spans[4].size))
            goto done;
        if (selection & ENROLLMENT_USE_MESH_TRUST) {
            size_t root_size = 0, issuer_size = 0;
            result = read_mesh_trust(false, &mesh_roots, &root_size);
            if (result != ESP_OK)
                goto done;
            if (mesh_roots)
                spans[1] = (struct wendy_conf_span){mesh_roots->der, root_size};
            if (selection & ENROLLMENT_LITE_INTERMEDIATES)
                result = read_mesh_trust(true, &mesh_issuers, &issuer_size);
            if (result != ESP_OK)
                goto done;
            if (mesh_issuers)
                spans[4] = (struct wendy_conf_span){mesh_issuers->der, issuer_size};
        }
        size_t total = 0, source_total = 0, sizes[5] = {0};
        result = ESP_ERR_INVALID_SIZE;
        for (size_t i = 0; i < 5; i++) {
            if (!(selection & (1U << i))) {
                spans[i] = (struct wendy_conf_span){0};
                continue;
            }
            size_t limit = (i == 1 || i == 4) ? WENDY_CONF_MAX_DEVICE_TRUST_BUNDLE
                             : i ? WENDY_CONF_MAX_TRUST_BUNDLE : WENDY_CONF_MAX_ENROLLMENT_DATA;
            if (spans[i].size > limit ||
                spans[i].size > WENDY_CONF_MAX_ENROLLMENT_DATA - source_total)
                goto done;
            source_total += spans[i].size;
            sizes[i] = spans[i].size;
            if (der && i && spans[i].size &&
                wendy_cert_bundle_measure(spans[i].data, spans[i].size, &sizes[i])) {
                result = ESP_ERR_INVALID_ARG;
                goto done;
            }
            if (sizes[i] > WENDY_CONF_MAX_ENROLLMENT_DATA - total)
                goto done;
            total += sizes[i];
        }
        _Static_assert(WENDY_CONF_MAX_ENROLLMENT_DATA < SIZE_MAX,
                       "enrollment snapshot must leave room for a trailing NUL");
        if (der && spans[1].size) {
            size_t hashed = 0;
            if (psa_crypto_init() != PSA_SUCCESS ||
                psa_hash_compute(PSA_ALG_SHA_256, spans[1].data, spans[1].size,
                                 data->device_roots_source_hash, 32, &hashed) != PSA_SUCCESS ||
                hashed != 32) {
                result = ESP_FAIL;
                goto done;
            }
        }
        /* Reuse the NVS allocation on the classical profile's common
         * roots-only path. Moving the DER over the record header leaves
         * room for the trailing NUL. No second copy of the pins is needed. */
        bool take_roots = mesh_roots && total == sizes[1] && sizes[1] == spans[1].size;
        if (take_roots) {
            memmove(mesh_roots, mesh_roots->der, total);
            data->storage = (uint8_t *)mesh_roots;
            mesh_roots = NULL;
        } else {
            data->storage = total ? malloc(total + 1) : NULL;
        }
        if (total && !data->storage) {
            result = ESP_ERR_NO_MEM;
            goto done;
        }
        size_t offset = 0;
        for (size_t i = 0; i < 5; i++) {
            if (!spans[i].size)
                continue;
            if (i == 1 && take_roots) {
                data->device_roots = (struct wendy_conf_span){data->storage, sizes[1]};
                offset += sizes[1];
                continue;
            }
            if (der && i) {
                size_t copied = 0;
                if (wendy_cert_bundle_import(spans[i].data, spans[i].size, data->storage + offset,
                                             sizes[i], &copied) ||
                    copied != sizes[i]) {
                    result = ESP_ERR_INVALID_ARG;
                    goto done;
                }
            } else {
                memcpy(data->storage + offset, spans[i].data, sizes[i]);
            }
            *copies[i] = (struct wendy_conf_span){data->storage + offset, sizes[i]};
            offset += sizes[i];
        }
        if (total)
            data->storage[total] = 0;
        *config = s_cache.conf.enrollment;
        memset(&config->signed_time, 0, sizeof config->signed_time);
        memset(&config->device_roots, 0, sizeof config->device_roots);
        memset(&config->tsa_roots, 0, sizeof config->tsa_roots);
        memset(&config->https_roots, 0, sizeof config->https_roots);
        memset(&config->lite_device_intermediates, 0, sizeof config->lite_device_intermediates);
        if (der)
            data->generation = s_generation;
        result = ESP_OK;
    }
done:
    free(mesh_roots);
    free(mesh_issuers);
    if (result != ESP_OK) {
        free(data->storage);
        memset(data, 0, sizeof *data);
    }
    pthread_mutex_unlock(&s_cache_lock);
    return result;
}

esp_err_t wendy_conf_copy_enrollment(WendyConfEnrollment *config,
    struct wendy_conf_enrollment_data *data)
{
    return copy_enrollment(config, data, ENROLLMENT_ALL, true);
}

esp_err_t wendy_conf_copy_enrollment_der(WendyConfEnrollment *config,
    struct wendy_conf_enrollment_data *data)
{
    return copy_enrollment(config, data, ENROLLMENT_ALL, true);
}

esp_err_t wendy_conf_copy_device_trust(WendyConfEnrollment *config,
    struct wendy_conf_enrollment_data *data)
{
    return copy_enrollment(config, data, ENROLLMENT_DEVICE_ROOTS | ENROLLMENT_USE_MESH_TRUST, true);
}

esp_err_t wendy_conf_copy_mesh_trust(WendyConfEnrollment *config,
                                     struct wendy_conf_enrollment_data *data)
{
    return copy_enrollment(config, data, ENROLLMENT_DEVICE_ROOTS | ENROLLMENT_LITE_INTERMEDIATES |
                           ENROLLMENT_USE_MESH_TRUST,
                           true);
}

esp_err_t wendy_conf_copy_lite_intermediates(uint64_t generation, uint8_t **der, size_t *size)
{
    if (!der || !size)
        return ESP_ERR_INVALID_ARG;
    *der = NULL;
    *size = 0;
    esp_err_t result = ESP_ERR_INVALID_STATE;
    struct mesh_trust_record *record = NULL;
    pthread_mutex_lock(&s_cache_lock);
    if (!s_cache.valid || !generation || generation != s_generation)
        goto done;
    struct wendy_conf_span source = s_cache.lite_device_intermediates;
    size_t refreshed_size;
    result = read_mesh_trust(true, &record, &refreshed_size);
    if (result != ESP_OK)
        goto done;
    if (record) {
        memmove(record, record->der, refreshed_size);
        *der = (uint8_t *)record;
        *size = refreshed_size;
        record = NULL;
        goto done;
    }
    if (!source.size) {
        result = ESP_OK;
        goto done;
    }
    size_t extent = 0;
    result = ESP_ERR_INVALID_ARG;
    if (!s_cache.conf.enrollment.provision_trust ||
        source.size > WENDY_CONF_MAX_DEVICE_TRUST_BUNDLE ||
        wendy_cert_bundle_measure(source.data, source.size, &extent))
        goto done;
    uint8_t *copy = malloc(extent);
    if (!copy) {
        result = ESP_ERR_NO_MEM;
        goto done;
    }
    if (wendy_cert_bundle_import(source.data, source.size, copy, extent, size) || *size != extent) {
        free(copy);
        *size = 0;
        goto done;
    }
    *der = copy;
    result = ESP_OK;
done:
    free(record);
    pthread_mutex_unlock(&s_cache_lock);
    return result;
}

esp_err_t wendy_conf_copy_time_trust(WendyConfEnrollment *config,
                                     struct wendy_conf_enrollment_data *data, bool bootstrap,
                                     bool https)
{
    unsigned selection = ENROLLMENT_TSA_ROOTS | (bootstrap ? ENROLLMENT_TIME : 0U) |
                         (https ? ENROLLMENT_HTTPS_ROOTS : 0U);
    return copy_enrollment(config, data, selection, true);
}

bool wendy_conf_snapshot_current(uint64_t generation)
{
    pthread_mutex_lock(&s_cache_lock);
    bool current = s_cache.valid && generation && generation == s_generation;
    pthread_mutex_unlock(&s_cache_lock);
    return current;
}

void wendy_conf_get_enrolled_ids(char tenant[37], char device[65])
{
    _Static_assert(sizeof s_cache.conf.enrollment.tenant_id == 37 &&
                   sizeof s_cache.conf.enrollment.device_id == 65, "enrollment id sizes");
    tenant[0] = device[0] = 0;
    pthread_mutex_lock(&s_cache_lock);
    if (s_cache.valid && s_cache.conf.has_enrollment) {
        memcpy(tenant, s_cache.conf.enrollment.tenant_id, 37);
        memcpy(device, s_cache.conf.enrollment.device_id, 65);
        tenant[36] = device[64] = 0;
    }
    pthread_mutex_unlock(&s_cache_lock);
}

void wendy_conf_enrollment_identity(char tenant[37], char device[65])
{
    wendy_conf_get_enrolled_ids(tenant, device);
}

bool wendy_conf_has_enrollment(void)
{
    pthread_mutex_lock(&s_cache_lock);
    bool present = s_enrollment_required;
    pthread_mutex_unlock(&s_cache_lock);
    return present;
}

bool wendy_conf_is_current(void)
{
    pthread_mutex_lock(&s_cache_lock);
    bool current = s_cache.valid;
    pthread_mutex_unlock(&s_cache_lock);
    return current;
}
