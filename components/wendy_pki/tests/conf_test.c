/* Test the actual flash configuration encoder/decoder and owned snapshots. */
#define CONFIG_WENDY_DEVICE_NAME_BUF_SIZE 64
#define CONFIG_WENDY_DEVICE_NAME_DEFAULT_PREFIX "wendy"
#include "../../wendy_conf/src/wendy_conf.c"
#include "pb_encode.h"
#include <assert.h>

const uint8_t default_cert_der_start[] = {0}, default_cert_der_end[] = {0};
const uint8_t default_key_der_start[] = {0}, default_key_der_end[] = {0};
static uint8_t flash[80 * 1024];
static const esp_partition_t partition = {sizeof flash, 4096};
esp_err_t esp_read_mac(uint8_t *mac, int type)
{
    memset(mac, 1, 6);
    return ESP_OK;
}
_Noreturn void esp_system_abort(const char *message) { abort(); }
const esp_partition_t *esp_partition_find_first(int t, esp_partition_subtype_t s, const char *name)
{
    return &partition;
}
esp_err_t esp_partition_mmap(const esp_partition_t *p, size_t off, size_t size, int type,
                             const void **out, esp_partition_mmap_handle_t *handle)
{
    assert(off + size <= sizeof flash);
    *out = flash + off;
    *handle = 1;
    return ESP_OK;
}
void esp_partition_munmap(esp_partition_mmap_handle_t h) {}
esp_err_t esp_partition_erase_range(const esp_partition_t *p, size_t off, size_t size)
{
    assert(off + size <= sizeof flash);
    memset(flash + off, 0xff, size);
    return ESP_OK;
}
esp_err_t esp_partition_write(const esp_partition_t *p, size_t off, const void *data, size_t size)
{
    assert(off + size <= sizeof flash);
    memcpy(flash + off, data, size);
    return ESP_OK;
}

static bool encode_span(pb_ostream_t *stream, const pb_field_t *field, void *const *arg)
{
    const struct wendy_conf_span *span = *arg;
    return pb_encode_tag_for_field(stream, field) &&
           pb_encode_string(stream, span->data, span->size);
}
static esp_err_t write_config(const char *root, size_t root_size, const void *seed, size_t seed_size)
{
    WendyConf conf = WendyConf_init_zero;
    conf.has_enrollment = true;
    strcpy(conf.enrollment.tenant_id, "2558fd76-afc7-466e-9613-6b715296a526");
    strcpy(conf.enrollment.device_id, "lite-test");
    conf.enrollment.provision_trust = true;
    struct wendy_conf_span roots = {root, root_size}, time_seed = {seed, seed_size};
    conf.enrollment.device_roots = (pb_callback_t){.funcs.encode = encode_span, .arg = &roots};
    conf.enrollment.tsa_roots = conf.enrollment.https_roots = conf.enrollment.device_roots;
    conf.enrollment.signed_time = (pb_callback_t){.funcs.encode = encode_span, .arg = &time_seed};
    uint8_t *encoded = malloc(sizeof flash);
    pb_ostream_t out = pb_ostream_from_buffer(encoded, sizeof flash);
    assert(pb_encode(&out, WendyConf_fields, &conf));
    esp_err_t result = wendy_conf_write(encoded, out.bytes_written, WENDY_CONF_WRITE_MODE_UPDATE);
    free(encoded);
    return result;
}
int main(void)
{
    memset(flash, 0xff, sizeof flash);
    wendy_conf_init();
    WendyConfEnrollment cfg;
    struct wendy_conf_enrollment_data first, next;
    assert(wendy_conf_copy_enrollment(&cfg, &first) == ESP_ERR_INVALID_STATE);
    assert(!first.storage);
    assert(write_config("first-root", 10, "seed", 4) == ESP_OK);
    _load_conf(); /* Simulate restart and remapping the persisted partition. */
    assert(wendy_conf_copy_enrollment(&cfg, &first) == ESP_OK);
    assert(cfg.provision_trust && !cfg.device_roots.arg && !cfg.signed_time.arg);
    assert(first.device_roots.size == 10 && !memcmp(first.device_roots.data, "first-root", 10));
    assert(first.tsa_roots.size == 10 && !memcmp(first.tsa_roots.data, "first-root", 10));
    assert(first.https_roots.size == 10 && !memcmp(first.https_roots.data, "first-root", 10));
    assert(first.signed_time.size == 4 && !memcmp(first.signed_time.data, "seed", 4));
    assert(write_config("second-root", 11, NULL, 0) == ESP_OK);
    assert(!memcmp(first.device_roots.data, "first-root", 10));
    _load_conf();
    assert(wendy_conf_copy_enrollment(&cfg, &next) == ESP_OK);
    assert(next.device_roots.size == 11 && !memcmp(next.device_roots.data, "second-root", 11));
    free(first.storage);
    free(next.storage);
    WendyConf wifi_update = WendyConf_init_zero;
    wifi_update.has_wifi = true;
    uint8_t update[32];
    pb_ostream_t update_stream = pb_ostream_from_buffer(update, sizeof update);
    assert(pb_encode(&update_stream, WendyConf_fields, &wifi_update));
    assert(wendy_conf_write(update, update_stream.bytes_written, WENDY_CONF_WRITE_MODE_UPDATE) == ESP_OK);
    _load_conf();
    assert(wendy_conf_copy_enrollment(&cfg, &next) == ESP_OK);
    assert(cfg.provision_trust && next.device_roots.size == 11);
    free(next.storage);
    uint8_t *large = calloc(1, 60000);
    assert(write_config((char *)large, WENDY_CONF_MAX_TRUST_BUNDLE + 1, NULL, 0) == ESP_ERR_INVALID_SIZE);
    assert(write_config((char *)large, 4000, large, 60000) == ESP_ERR_INVALID_SIZE);
    assert(write_config(NULL, 0, NULL, 0) == ESP_ERR_INVALID_ARG);
    /* Rejected uploads leave the previous enrollment intact. */
    _invalidate_cache();
    _load_conf();
    assert(wendy_conf_copy_enrollment(&cfg, &next) == ESP_OK);
    assert(next.device_roots.size == 11 && !memcmp(next.device_roots.data, "second-root", 11));
    free(next.storage);
    /* Corrupted/oversized persisted data still fails the read-side bound. */
    s_cache.device_roots.size = WENDY_CONF_MAX_TRUST_BUNDLE + 1;
    assert(wendy_conf_copy_enrollment(&cfg, &next) == ESP_ERR_INVALID_SIZE && !next.storage);
    free(large);
    puts("enrollment configuration persistence tests passed");
}
