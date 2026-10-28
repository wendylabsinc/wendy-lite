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
static unsigned erase_calls, write_calls;
static bool fail_erase;
static unsigned fail_write_at;
static size_t partial_write_size;
static unsigned corrupt_write_at;
/* Model committed storage separately from an open handle's pending writes.
 * Closing without a successful commit, or rebooting, discards pending writes. */
static uint8_t durable_journal[sizeof flash + MAGIC_LEN];
static uint8_t staged_journal[sizeof durable_journal];
static size_t durable_journal_size, staged_journal_size;
static bool durable_journal_present, staged_journal_present, journal_open;
static bool fail_journal_open, fail_journal_set, fail_journal_read, fail_journal_erase;
static unsigned journal_commits, fail_journal_commit_at;

esp_err_t nvs_open_from_partition(const char *part, const char *name, int mode, nvs_handle_t *h)
{
    assert(!strcmp(part, "wendy_pki") && !strcmp(name, "conf_recovery"));
    assert(mode == NVS_READWRITE && !journal_open);
    if (fail_journal_open) return ESP_FAIL;
    journal_open = true;
    staged_journal_present = durable_journal_present;
    staged_journal_size = durable_journal_size;
    memcpy(staged_journal, durable_journal, durable_journal_size);
    *h = 1;
    return ESP_OK;
}
void nvs_close(nvs_handle_t h)
{
    assert(h == 1 && journal_open);
    journal_open = false;
}
esp_err_t nvs_get_blob(nvs_handle_t h, const char *name, void *out, size_t *size)
{
    assert(h == 1 && journal_open && !strcmp(name, "retained"));
    if (fail_journal_read) return ESP_FAIL;
    if (!staged_journal_present) return ESP_ERR_NVS_NOT_FOUND;
    if (out) {
        if (*size < staged_journal_size) return ESP_ERR_INVALID_SIZE;
        memcpy(out, staged_journal, staged_journal_size);
    }
    *size = staged_journal_size;
    return ESP_OK;
}
esp_err_t nvs_set_blob(nvs_handle_t h, const char *name, const void *data, size_t size)
{
    assert(h == 1 && journal_open && !strcmp(name, "retained"));
    assert(size <= sizeof staged_journal);
    if (fail_journal_set) return ESP_FAIL;
    memcpy(staged_journal, data, size);
    staged_journal_size = size;
    staged_journal_present = true;
    return ESP_OK;
}
esp_err_t nvs_erase_key(nvs_handle_t h, const char *name)
{
    assert(h == 1 && journal_open && !strcmp(name, "retained"));
    /* Journal removal must follow successful flash verification. */
    assert(s_cache.valid && s_cache.pb_size + MAGIC_LEN == staged_journal_size);
    assert(!memcmp(s_cache.pb_data, staged_journal + MAGIC_LEN, s_cache.pb_size));
    if (fail_journal_erase) return ESP_FAIL;
    staged_journal_present = false;
    staged_journal_size = 0;
    return ESP_OK;
}
esp_err_t nvs_commit(nvs_handle_t h)
{
    assert(h == 1 && journal_open);
    if (++journal_commits == fail_journal_commit_at) return ESP_FAIL;
    durable_journal_present = staged_journal_present;
    durable_journal_size = staged_journal_size;
    memcpy(durable_journal, staged_journal, durable_journal_size);
    return ESP_OK;
}
esp_err_t esp_read_mac(uint8_t *mac, int type)
{
    memset(mac, 1, 6);
    return ESP_OK;
}
_Noreturn void esp_system_abort(const char *message) { abort(); }
const esp_partition_t *esp_partition_find_first(int t, esp_partition_subtype_t s, const char *name)
{
    assert(t == ESP_PARTITION_TYPE_DATA && s == WENDY_CONF_PART_SUBTYPE);
    assert(!strcmp(name, "wendy_conf"));
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
    assert(p == &partition);
    assert(off + size <= sizeof flash);
    erase_calls++;
    if (fail_erase)
        return ESP_FAIL;
    memset(flash + off, 0xff, size);
    return ESP_OK;
}
esp_err_t esp_partition_write(const esp_partition_t *p, size_t off, const void *data, size_t size)
{
    assert(p == &partition);
    assert(off + size <= sizeof flash);
    write_calls++;
    if (write_calls == fail_write_at) {
        assert(partial_write_size <= size);
        memcpy(flash + off, data, partial_write_size);
        return ESP_FAIL;
    }
    memcpy(flash + off, data, size);
    if (write_calls == corrupt_write_at) {
        assert(size > 0);
        flash[off + size - 1] ^= 1;
    }
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
    strcpy(conf.enrollment.device_id, "00000000-0000-4000-8000-000000000004");
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

/* Different wire types and large unknown tags must survive byte-for-byte,
 * including the deliberately non-minimal encoding of the final varint. */
static const uint8_t retained_fields[] = {
    0x0a, 9, 't', 'e', 's', 't', '-', 'n', 'a', 'm', 'e',
    0x12, 12, 0x0a, 10, 0x0a, 4, 's', 's', 'i', 'd', 0x12, 2, 'p', 'w',
    0x28, 0x96, 0x01,
    0x8d, 0x02, 0x11, 0x22, 0x33, 0x44,
    0x91, 0x02, 1, 2, 3, 4, 5, 6, 7, 8,
    0x9a, 0x02, 3, 'x', 'y', 'z',
    0xe0, 0x12, 0x81, 0x00,
};
static const uint8_t enrollment_fields[] = {
    0x22, 5, 0x1a, 3, 't', 'o', 'k',
    0x1a, 11, 0x08, 1, 0x2a, 1, 'k', 0x32, 1, 'c', 0x3a, 1, 'r',
    /* Duplicate enrollment fields are removed too. */
    0x22, 2, 0x0a, 0,
};

/* Model configuration persisted by an older firmware, bypassing upload checks. */
static void load_stored_config(const uint8_t *encoded, size_t size)
{
    _invalidate_cache();
    s_enrollment_required = false; /* A new boot starts with no cached policy. */
    assert(size + HEADER_LEN <= sizeof flash);
    memset(flash, 0xff, sizeof flash);
    memcpy(flash, MAGIC, MAGIC_LEN);
    for (size_t i = 0; i < 4; i++)
        flash[MAGIC_LEN + i] = (size >> (8 * i)) & 0xff;
    memcpy(flash + HEADER_LEN, encoded, size);
    _load_conf();
}

static void load_reset_fixture(bool keep_fields)
{
    uint8_t encoded[sizeof retained_fields + sizeof enrollment_fields];
    size_t size = 0;
    _invalidate_cache();
    memset(flash, 0xff, sizeof flash);
    fail_erase = false;
    fail_write_at = corrupt_write_at = 0;
    assert(!journal_open);
    durable_journal_present = false;
    durable_journal_size = 0;
    fail_journal_open = fail_journal_read = fail_journal_set = fail_journal_erase = false;
    fail_journal_commit_at = 0;
    if (keep_fields) {
        memcpy(encoded, retained_fields, sizeof retained_fields);
        size = sizeof retained_fields;
    }
    memcpy(encoded + size, enrollment_fields, sizeof enrollment_fields);
    size += sizeof enrollment_fields;
    load_stored_config(encoded, size);
    assert(wendy_conf_has_enrollment());
}

static void assert_reset_config(bool keep_fields)
{
    assert(s_cache.valid);
    assert(!durable_journal_present);
    assert(!wendy_conf_has_enrollment());
    assert(s_cache.pb_size == (keep_fields ? sizeof retained_fields : 0));
    if (keep_fields) {
        assert(!memcmp(s_cache.pb_data, retained_fields, sizeof retained_fields));
        char name[16], ssid[16], password[16];
        wendy_conf_copy_span(name, sizeof name, wendy_conf_get_device_name());
        wendy_conf_copy_span(ssid, sizeof ssid, wendy_conf_get_network_ssid());
        wendy_conf_copy_span(password, sizeof password, wendy_conf_get_network_password());
        assert(!strcmp(name, "test-name") && !strcmp(ssid, "ssid") && !strcmp(password, "pw"));
    }
}

static void test_clear_enrollment(void)
{
    load_reset_fixture(true);
    _invalidate_cache(); /* The enrollment upload itself invalidates the cache. */
    assert(wendy_conf_clear_enrollment() == ESP_OK);
    assert_reset_config(true);
    unsigned erases = erase_calls, writes = write_calls;
    assert(wendy_conf_clear_enrollment() == ESP_OK);
    assert(erase_calls == erases && write_calls == writes);
    _invalidate_cache(); /* Retry after a restart or a cache-invalidating write. */
    assert(wendy_conf_clear_enrollment() == ESP_OK);
    assert_reset_config(true);
    assert(erase_calls == erases && write_calls == writes);

    load_reset_fixture(false);
    assert(wendy_conf_clear_enrollment() == ESP_OK);
    assert_reset_config(false);
    _invalidate_cache();
    assert(wendy_conf_clear_enrollment() == ESP_OK);
    assert_reset_config(false);
    /* Empty uploads remain rejected even though recovery can store an empty config. */
    assert(wendy_conf_write("", 0, WENDY_CONF_WRITE_MODE_REPLACE) == ESP_ERR_INVALID_ARG);

    load_reset_fixture(true);
    fail_erase = true;
    assert(wendy_conf_clear_enrollment() == ESP_FAIL);
    assert(!s_cache.valid);
    fail_erase = false;
    assert(wendy_conf_clear_enrollment() == ESP_OK);
    assert_reset_config(true);

    /* A header failure or partial payload write retains the durable journal.
     * A fresh cache after reboot must recover every retained field from it. */
    for (unsigned failed_write = 1; failed_write <= 2; failed_write++) {
        load_reset_fixture(true);
        fail_write_at = write_calls + failed_write;
        partial_write_size = 1;
        assert(wendy_conf_clear_enrollment() == ESP_FAIL);
        assert(!s_cache.valid);
        assert(durable_journal_present);
        erases = erase_calls;
        writes = write_calls;
        fail_write_at = 0;
        _invalidate_cache(); /* Simulate reboot without changing committed NVS. */
        assert(wendy_conf_clear_enrollment() == ESP_OK);
        assert_reset_config(true);
        assert(erase_calls == erases + 1 && write_calls == writes + 2);
    }

    _invalidate_cache();
    memset(flash, 0xff, sizeof flash);
    assert(wendy_conf_clear_enrollment() == ESP_ERR_INVALID_STATE);
}

static void test_clear_enrollment_journal(void)
{
    /* NVS errors before the journal is committed must not touch flash. */
    for (int failure = 0; failure < 4; failure++) {
        load_reset_fixture(true);
        fail_journal_open = failure == 0;
        fail_journal_read = failure == 1;
        fail_journal_set = failure == 2;
        fail_journal_commit_at = failure == 3 ? journal_commits + 1 : 0;
        unsigned erases = erase_calls, writes = write_calls;
        assert(wendy_conf_clear_enrollment() == ESP_FAIL);
        assert(wendy_conf_has_enrollment());
        assert(!durable_journal_present && !journal_open);
        assert(erase_calls == erases && write_calls == writes);
        fail_journal_open = fail_journal_read = fail_journal_set = false;
        fail_journal_commit_at = 0;
        _invalidate_cache();
        assert(wendy_conf_clear_enrollment() == ESP_OK);
        assert_reset_config(true);
    }

    /* Retry a completed flash write if power failed before journal cleanup.
     * No second flash erase is needed when its exact bytes already match. */
    for (int failure = 0; failure < 2; failure++) {
        load_reset_fixture(true);
        fail_journal_erase = failure == 0;
        fail_journal_commit_at = failure == 1 ? journal_commits + 2 : 0;
        assert(wendy_conf_clear_enrollment() == ESP_FAIL);
        assert(durable_journal_present && wendy_conf_has_enrollment());
        unsigned erases = erase_calls, writes = write_calls;
        fail_journal_erase = false;
        fail_journal_commit_at = 0;
        _invalidate_cache();
        assert(wendy_conf_clear_enrollment() == ESP_OK);
        assert_reset_config(true);
        assert(erase_calls == erases && write_calls == writes);
    }

    /* Successful write calls alone are insufficient: exact readback must match. */
    load_reset_fixture(true);
    corrupt_write_at = write_calls + 2;
    assert(wendy_conf_clear_enrollment() == ESP_ERR_INVALID_STATE);
    assert(s_cache.valid && durable_journal_present);
    assert(memcmp(s_cache.pb_data, retained_fields, sizeof retained_fields));
    corrupt_write_at = 0;
    _invalidate_cache();
    assert(wendy_conf_clear_enrollment() == ESP_OK);
    assert_reset_config(true);

    /* The journal can also restore an empty retained configuration. */
    load_reset_fixture(false);
    fail_write_at = write_calls + 1;
    partial_write_size = 1;
    assert(wendy_conf_clear_enrollment() == ESP_FAIL);
    assert(durable_journal_present && durable_journal_size == MAGIC_LEN);
    fail_write_at = 0;
    _invalidate_cache();
    assert(wendy_conf_clear_enrollment() == ESP_OK);
    assert_reset_config(false);

    /* A corrupt or unexpected journal must not authorize a destructive write. */
    load_reset_fixture(true);
    durable_journal_present = true;
    durable_journal_size = MAGIC_LEN;
    memcpy(durable_journal, "BAD!", MAGIC_LEN);
    unsigned erases = erase_calls, writes = write_calls;
    assert(wendy_conf_clear_enrollment() == ESP_ERR_INVALID_STATE);
    assert(erase_calls == erases && write_calls == writes);
    memcpy(durable_journal, RECOVERY_MAGIC, MAGIC_LEN);
    memcpy(durable_journal + MAGIC_LEN, enrollment_fields, sizeof enrollment_fields);
    durable_journal_size += sizeof enrollment_fields;
    assert(wendy_conf_clear_enrollment() == ESP_ERR_INVALID_STATE);
    assert(erase_calls == erases && write_calls == writes);
}

static void test_retired_credentials(void)
{
    const uint8_t retired[] = {0x1a, 11, 0x08, 1, 0x2a, 1, 'k', 0x32, 1, 'c', 0x3a, 1, 'r'};
    const uint8_t wifi_update[] = {0x12, 0};
    load_stored_config(retired, sizeof retired);
    /* Old credentials cannot authenticate, and cannot enable anonymous TLS. */
    assert(wendy_conf_has_enrollment());
    WendyConfEnrollment cfg;
    struct wendy_conf_enrollment_data data;
    assert(wendy_conf_copy_enrollment(&cfg, &data) == ESP_ERR_INVALID_STATE);
    assert(!data.storage);
    unsigned erases = erase_calls, writes = write_calls;
    assert(wendy_conf_write(retired, sizeof retired, WENDY_CONF_WRITE_MODE_REPLACE) == ESP_ERR_INVALID_ARG);
    assert(wendy_conf_write(retired, sizeof retired, WENDY_CONF_WRITE_MODE_UPDATE) == ESP_ERR_INVALID_ARG);
    assert(erase_calls == erases && write_calls == writes);
    assert(wendy_conf_has_enrollment());
    /* Wi-Fi updates preserve old fields and their authentication requirement. */
    assert(wendy_conf_write(wifi_update, sizeof wifi_update, WENDY_CONF_WRITE_MODE_UPDATE) == ESP_OK);
    assert(!wendy_conf_is_current() && wendy_conf_has_enrollment());
    _load_conf();
    assert(wendy_conf_has_enrollment());
    assert(wendy_conf_clear_enrollment() == ESP_OK);
    assert(!wendy_conf_has_enrollment());
    assert(s_cache.pb_size == sizeof wifi_update);
    assert(!memcmp(s_cache.pb_data, wifi_update, sizeof wifi_update));
}

static void test_enrollment_policy_survives_writes(void)
{
    const uint8_t wifi_only[] = {0x12, 0};
    for (int failure = 0; failure < 2; failure++) {
        load_stored_config(wifi_only, sizeof wifi_only);
        assert(!wendy_conf_has_enrollment());
        fail_erase = failure != 0;
        assert(write_config("root", 4, NULL, 0) == (failure ? ESP_FAIL : ESP_OK));
        /* Even the first enrollment upload must revoke existing anonymous access. */
        assert(!wendy_conf_is_current() && wendy_conf_has_enrollment());
        fail_erase = false;
        _load_conf();
        assert(wendy_conf_has_enrollment());
        assert(wendy_conf_clear_enrollment() == ESP_OK);
        assert(!wendy_conf_has_enrollment());
    }
    assert(write_config("root", 4, NULL, 0) == ESP_OK);
    _load_conf();
    fail_erase = true;
    assert(wendy_conf_write(wifi_only, sizeof wifi_only, WENDY_CONF_WRITE_MODE_UPDATE) == ESP_FAIL);
    assert(!wendy_conf_is_current() && wendy_conf_has_enrollment());
    fail_erase = false;
    _load_conf();
    assert(wendy_conf_has_enrollment());
    assert(wendy_conf_clear_enrollment() == ESP_OK);
    assert(!wendy_conf_has_enrollment());
}

static int der_snapshots(const char *path)
{
    FILE *f=fopen(path,"rb");assert(f);
    assert(!fseek(f,0,SEEK_END));size_t pem_size=(size_t)ftell(f);rewind(f);
    uint8_t *pem=malloc(pem_size);assert(pem && fread(pem,1,pem_size,f)==pem_size);fclose(f);
    size_t der_size=0;assert(!wendy_cert_bundle_measure(pem,pem_size,&der_size));
    uint8_t *der=malloc(der_size);assert(der);
    assert(!wendy_cert_bundle_import(pem,pem_size,der,der_size,&der_size));
    memset(flash,0xff,sizeof flash);wendy_conf_init();
    assert(write_config((const char*)pem,pem_size,"seed",4)==ESP_OK);_load_conf();
    WendyConfEnrollment cfg;struct wendy_conf_enrollment_data full,device,clock;
    assert(wendy_conf_copy_enrollment(&cfg,&full)==ESP_OK);
    assert(full.signed_time.size==4 && !memcmp(full.signed_time.data,"seed",4));
    assert(full.device_roots.size==der_size && full.tsa_roots.size==der_size &&
           full.https_roots.size==der_size && !memcmp(full.device_roots.data,der,der_size));
    assert(wendy_conf_copy_device_trust(&cfg,&device)==ESP_OK);
    assert(device.device_roots.size==der_size && device.storage[der_size]==0);
    uint8_t hash[32];size_t hashed=0;
    assert(psa_hash_compute(PSA_ALG_SHA_256,pem,pem_size,hash,32,&hashed)==PSA_SUCCESS && hashed==32);
    assert(!memcmp(hash,device.device_roots_source_hash,32));
    assert(wendy_conf_copy_time_trust(&cfg,&clock,false,true)==ESP_OK);
    assert(clock.tsa_roots.size==der_size && clock.https_roots.size==der_size && !clock.device_roots.size);
    assert(write_config((const char*)der,der_size,NULL,0)==ESP_OK);_load_conf();
    assert(!memcmp(device.device_roots.data,der,der_size));
    struct wendy_conf_enrollment_data next;
    assert(wendy_conf_copy_device_trust(&cfg,&next)==ESP_OK && next.device_roots.size==der_size);
    assert(!memcmp(next.device_roots.data,der,der_size));
    free(full.storage);free(device.storage);free(clock.storage);free(next.storage);free(der);free(pem);
    puts("PASS DER enrollment/time/device snapshots and immutable ownership across writes");return 0;
}
int main(int argc,char **argv)
{
    if(argc==3 && !strcmp(argv[1],"--der-snapshots"))return der_snapshots(argv[2]);
    memset(flash, 0xff, sizeof flash);
    wendy_conf_init();
    char public_tenant[37] = "stale", public_device[65] = "stale";
    wendy_conf_enrollment_identity(public_tenant, public_device);
    assert(!public_tenant[0] && !public_device[0]);
    WendyConfEnrollment cfg;
    struct wendy_conf_enrollment_data first, next;
    assert(wendy_conf_copy_enrollment(&cfg, &first) == ESP_ERR_INVALID_STATE);
    assert(!first.storage);
    assert(write_config("\x30\x08" "first-r!", 10, "seed", 4) == ESP_OK);
    _load_conf(); /* Simulate restart and remapping the persisted partition. */
    assert(wendy_conf_copy_enrollment(&cfg, &first) == ESP_OK);
    wendy_conf_enrollment_identity(public_tenant, public_device);
    assert(!strcmp(public_tenant, cfg.tenant_id) && !strcmp(public_device, cfg.device_id));
    assert(cfg.provision_trust && !cfg.device_roots.arg && !cfg.signed_time.arg);
    assert(first.device_roots.size == 10 && !memcmp(first.device_roots.data, "\x30\x08" "first-r!", 10));
    assert(first.tsa_roots.size == 10 && !memcmp(first.tsa_roots.data, "\x30\x08" "first-r!", 10));
    assert(first.https_roots.size == 10 && !memcmp(first.https_roots.data, "\x30\x08" "first-r!", 10));
    assert(first.signed_time.size == 4 && !memcmp(first.signed_time.data, "seed", 4));
    struct wendy_conf_enrollment_data device_only;
    assert(wendy_conf_copy_device_trust(&cfg,&device_only)==ESP_OK);
    assert(device_only.device_roots.data==device_only.storage);
    assert(device_only.device_roots.size==10 && device_only.storage[10]==0);
    assert(!memcmp(device_only.storage,"\x30\x08" "first-r!",10));
    assert(!device_only.signed_time.size && !device_only.signed_time.data);
    assert(!device_only.tsa_roots.size && !device_only.tsa_roots.data);
    assert(!device_only.https_roots.size && !device_only.https_roots.data);
    struct wendy_conf_enrollment_data time_only;
    assert(wendy_conf_copy_time_trust(&cfg,&time_only,false,false)==ESP_OK);
    assert(wendy_conf_snapshot_current(time_only.generation));
    assert(time_only.tsa_roots.size==10 && time_only.tsa_roots.data==time_only.storage);
    assert(!time_only.device_roots.size && !time_only.https_roots.size && !time_only.signed_time.size);
    assert(write_config("\x30\x09" "second-r!", 11, NULL, 0) == ESP_OK);
    assert(!wendy_conf_snapshot_current(time_only.generation));
    assert(!memcmp(time_only.tsa_roots.data,"\x30\x08" "first-r!",10));
    free(time_only.storage);
    assert(!memcmp(device_only.storage,"\x30\x08" "first-r!",10));
    free(device_only.storage);
    wendy_conf_enrollment_identity(public_tenant, public_device);
    assert(!public_tenant[0] && !public_device[0]);
    assert(!memcmp(first.device_roots.data, "\x30\x08" "first-r!", 10));
    _load_conf();
    assert(wendy_conf_copy_enrollment(&cfg, &next) == ESP_OK);
    assert(next.device_roots.size == 11 && !memcmp(next.device_roots.data, "\x30\x09" "second-r!", 11));
    free(first.storage);
    free(next.storage);
    WendyConf wifi_update = WendyConf_init_zero;
    wifi_update.has_wifi = true;
    uint8_t update[32];
    pb_ostream_t update_stream = pb_ostream_from_buffer(update, sizeof update);
    assert(pb_encode(&update_stream, WendyConf_fields, &wifi_update));
    /* A network Wi-Fi upload cannot introduce any other root field, including
     * unknown high tags, duplicate Wi-Fi fields, or malformed messages. */
    const uint8_t forbidden[][6] = {
        {0x0a, 0x00}, {0x22, 0x00}, {0x1a, 0x00}, {0x82, 0x02, 0x00},
        {0x12, 0x00, 0x22, 0x00}, {0x12, 0x00, 0x12, 0x00}, {0x12, 0x03, 0x00},
    };
    const size_t lengths[] = {2, 2, 2, 3, 4, 4, 3};
    unsigned before_erase = erase_calls, before_write = write_calls;
    for (size_t i = 0; i < sizeof lengths / sizeof lengths[0]; i++)
        assert(wendy_conf_write(forbidden[i], lengths[i], WENDY_CONF_WRITE_MODE_WIFI_ONLY) == ESP_ERR_INVALID_ARG);
    assert(erase_calls == before_erase && write_calls == before_write);
    assert(wendy_conf_is_current() && wendy_conf_has_enrollment());
    assert(wendy_conf_write(update, update_stream.bytes_written, WENDY_CONF_WRITE_MODE_WIFI_ONLY) == ESP_OK);
    /* A second upload before reboot must not erase the now-unmapped identity. */
    assert(wendy_conf_write(update, update_stream.bytes_written, WENDY_CONF_WRITE_MODE_WIFI_ONLY) == ESP_ERR_INVALID_STATE);
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
    assert(next.device_roots.size == 11 && !memcmp(next.device_roots.data, "\x30\x09" "second-r!", 11));
    free(next.storage);
    /* Corrupted/oversized persisted data still fails the read-side bound. */
    s_cache.device_roots.size = WENDY_CONF_MAX_TRUST_BUNDLE + 1;
    assert(wendy_conf_copy_enrollment(&cfg, &next) == ESP_ERR_INVALID_SIZE && !next.storage);
    free(large);
    test_clear_enrollment();
    test_clear_enrollment_journal();
    /* Clear the deliberately corrupt journal from the preceding negative test. */
    durable_journal_present = false;
    durable_journal_size = 0;
    test_retired_credentials();
    test_enrollment_policy_survives_writes();
    puts("enrollment configuration persistence tests passed");
}
