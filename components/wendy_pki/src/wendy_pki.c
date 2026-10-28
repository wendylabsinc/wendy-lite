#include "cJSON.h"
#include "esp_log.h"
#include "esp_heap_caps.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "wendy_conf.h"
#include "wendy_cert_bundle.h"
#include "wendy_pki_internal.h"
#include "wendy_pki_der_cache.h"
#include "wendy_peer_identity.h"
#if CONFIG_WENDY_NET_PEER
#include "wendy_pki_native_prepare.h"
#endif
#if CONFIG_WENDY_NET_PEER
#include "http_parser.h"
#endif
#if CONFIG_WENDY_NET_PEER
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#endif
#include <unistd.h>
#if CONFIG_WENDY_NET_PEER
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netdb.h>
#endif
#include "wendy_pki_verify.h"
#include "wendy_pki_operator.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <mbedtls/pk.h>
#include "wendy_pki_crypto.h"
#include <mbedtls/x509_csr.h>

static const char *TAG = "wendy_pki";
/* Share the preferred receive capacity for device and operator handshakes.
 * It is an optional allocation: mandatory trust snapshots take precedence.
 * TLS record and handshake limits remain independently configured. */
#define NATIVE_TLS_INPUT_RESERVE PKI_TLS_INPUT_RESERVE
/* Historical NVS time is never a lease clock. Only a fresh nonce-bound reply
 * establishes this boot's monotonic anchor, under identity_lock. */
static time_t mesh_verified_seconds;
static int64_t mesh_verified_monotonic_us;
static uint64_t mesh_verified_generation;
static bool mesh_time_recent(void)
{
    int64_t age=esp_timer_get_time()-mesh_verified_monotonic_us;
    return mesh_verified_seconds > 0 && age >= 0 && age < INT64_C(300000000) &&
           wendy_conf_snapshot_current(mesh_verified_generation);
}
#if CONFIG_WENDY_NET_PEER
/* Under identity_lock. Cache only a complete successful bundle-policy check;
 * every call hashes its exact bytes and binds the configuration generation.
 * TLS still parses/verifies its selected path and session dates each time. */
static struct {
    uint8_t hash[32];
    uint64_t generation;
    bool valid;
} checked_device_roots;
static bool device_roots_checked(const struct wendy_conf_enrollment_data *data,
                                 uint8_t hash[32])
{
    return data->device_roots.data && data->device_roots.size &&
        !wendy_pki_sha256(data->device_roots.data,data->device_roots.size,hash) &&
        checked_device_roots.valid && checked_device_roots.generation==data->generation &&
        !memcmp(hash,checked_device_roots.hash,32);
}
static int check_device_roots(const struct wendy_conf_enrollment_data *data)
{
    uint8_t hash[32];
    if(device_roots_checked(data,hash))return 0;
    if(wendy_pki_verify_roots(data->device_roots.data,data->device_roots.size) ||
       wendy_pki_sha256(data->device_roots.data,data->device_roots.size,hash))return -1;
    memcpy(checked_device_roots.hash,hash,32);
    checked_device_roots.generation=data->generation;checked_device_roots.valid=true;
    return 0;
}
#endif
static pthread_once_t identity_once = PTHREAD_ONCE_INIT;
static esp_err_t identity_ready = ESP_FAIL;
/* Serialize issuance, status, and recovery so an in-flight enrollment cannot
 * restore a key or certificate after reset has erased it. */
static pthread_mutex_t identity_lock = PTHREAD_MUTEX_INITIALIZER;
static bool identity_use_allowed(void);
static int validate_config_and_trust(const WendyConfEnrollment *cfg,
    struct wendy_conf_enrollment_data *data);
#if CONFIG_WENDY_NET_PEER || CONFIG_WENDY_NET_NAN
static int select_time_trust(const WendyConfEnrollment *cfg,
    struct wendy_conf_enrollment_data *data,bool https);
#endif
static atomic_bool identity_resetting;
/* These survive mesh shutdown and certificate renewal. Only a reboot may
 * reserve another range or persist another verified clock high-water. */
#define MESH_REVISION_BOOT_RANGE (UINT64_C(1) << 32)
static pthread_mutex_t revision_lock = PTHREAD_MUTEX_INITIALIZER;
static struct {
    bool attempted, ready;
    uint64_t next, limit;
} boot_revisions;
/* Own identity/time preparation may persist one verified TSA-floor advance
 * per boot. Later proofs advance the RAM high-water; reboot resumes from the
 * first durable advance. No peer routes, proofs or lifecycle events write it. */
static struct {
    bool loaded, attempted, failed;
    int64_t high_water;
} boot_floor;
bool wendy_pki_reset_in_progress(void) { return atomic_load(&identity_resetting); }
static void init_identity(void)
{
    // Identity loss requires operator recovery. Never erase this partition automatically.
    identity_ready = nvs_flash_init_partition("wendy_pki");
}
static esp_err_t open_identity(nvs_handle_t *handle)
{
    pthread_once(&identity_once, init_identity);
    if (identity_ready != ESP_OK)
        return identity_ready;
    return nvs_open_from_partition("wendy_pki", "identity", NVS_READWRITE, handle);
}
/* Only the identity/bootstrap worker calls this, under identity_lock. The
 * durable key is retained across enrollment reset as well as renewal. */
#if CONFIG_WENDY_NET_PEER || defined(WENDY_PKI_BOOT_PERSISTENCE_HOST_TEST)
static int reserve_boot_revisions(nvs_handle_t handle)
{
    pthread_mutex_lock(&revision_lock);
    if (!boot_revisions.attempted) {
        boot_revisions.attempted = true;
        uint64_t reserved = 0;
        size_t size = sizeof reserved;
        esp_err_t status = nvs_get_blob(handle,"mesh_revision",&reserved,&size);
        if ((status == ESP_ERR_NVS_NOT_FOUND || (status == ESP_OK && size == sizeof reserved)) &&
            reserved < UINT64_MAX - MESH_REVISION_BOOT_RANGE) {
            uint64_t next = reserved + MESH_REVISION_BOOT_RANGE;
            if (nvs_set_blob(handle,"mesh_revision",&next,sizeof next) == ESP_OK &&
                nvs_commit(handle) == ESP_OK) {
                boot_revisions.next = reserved + 1;
                boot_revisions.limit = next + 1;
                boot_revisions.ready = true;
            }
        }
    }
    int result = boot_revisions.ready ? 0 : -1;
    pthread_mutex_unlock(&revision_lock);
    return result;
}
#endif
esp_err_t wendy_pki_mesh_revision_next(uint64_t *out)
{
    if (!out) return ESP_ERR_INVALID_ARG;
    if (wendy_pki_reset_in_progress() || !wendy_conf_is_current()) return ESP_ERR_INVALID_STATE;
    if (pthread_mutex_trylock(&revision_lock)) return ESP_ERR_TIMEOUT;
    esp_err_t result = ESP_ERR_INVALID_STATE;
    if (boot_revisions.ready && boot_revisions.next < boot_revisions.limit) {
        *out = boot_revisions.next++;
        result = ESP_OK;
    }
    pthread_mutex_unlock(&revision_lock);
    return result;
}
static void erase(void *p, size_t n)
{
    volatile uint8_t *q = p;
    while (n--)
        *q++ = 0;
}
static int load_blob(nvs_handle_t h, const char *name, uint8_t **out, size_t *n)
{
    *out = NULL;
    *n = 0;
    if (nvs_get_blob(h, name, NULL, n) != ESP_OK || !*n || *n > PKI_MAX_RESPONSE)
        return -1;
    *out = calloc(1, *n + 1);
    if (!*out)
        return -1;
    if (nvs_get_blob(h, name, *out, n) != ESP_OK)
    {
        free(*out);
        *out = NULL;
        return -1;
    }
    return 0;
}
/* Existing provisioning/issuance records may be PEM. Runtime consumers only
 * receive DER. Import in place, then shrink; never produce PEM for TLS. */
static int import_certificate(uint8_t **bytes,size_t *size)
{
    size_t decoded=0;
    if(!*bytes || wendy_cert_bundle_measure(*bytes,*size,&decoded) ||
       wendy_cert_bundle_import(*bytes,*size,*bytes,*size,&decoded))return -1;
    uint8_t *compact=realloc(*bytes,decoded+1);if(compact)*bytes=compact;
    (*bytes)[decoded]=0;*size=decoded;return 0;
}
static int load_certificate(nvs_handle_t h,const char *name,uint8_t **bytes,size_t *size)
{
    return load_blob(h,name,bytes,size) || import_certificate(bytes,size) ? -1:0;
}
#if CONFIG_WENDY_NET_PEER
struct public_der_context {
    struct pki_der_source source;
    uint64_t generation;
    uint32_t certificate_epoch;
};
static int public_der_metadata(void *context,struct wendy_pki_mesh_public_index *out)
{
    const struct public_der_context *source=context;
    *out=(struct wendy_pki_mesh_public_index){.count=source->source.count,
        .config_generation=source->generation,.certificate_epoch=source->certificate_epoch};
    memcpy(out->hashes,source->source.hashes,sizeof out->hashes);
    memcpy(out->sizes,source->source.sizes,sizeof out->sizes);
    return 0;
}
static int public_trust_load(void *context, uint8_t **bytes, size_t *size)
{
    struct public_der_context *source = context;
    *bytes = NULL;
    *size = 0;
    WendyConfEnrollment cfg = WendyConfEnrollment_init_zero;
    struct wendy_conf_enrollment_data data = {0};
    int result = -1;
    pthread_mutex_lock(&identity_lock);
    if (identity_use_allowed() && wendy_conf_is_current() &&
        wendy_conf_copy_device_trust(&cfg, &data) == ESP_OK &&
        data.generation == source->generation && data.device_roots.size)
    {
        memmove(data.storage, data.device_roots.data, data.device_roots.size);
        data.storage[data.device_roots.size] = 0;
        *bytes = data.storage;
        *size = data.device_roots.size;
        data.storage = NULL;
        result = 0;
    }
    free(data.storage);
    erase(cfg.token, sizeof cfg.token);
    pthread_mutex_unlock(&identity_lock);
    return result;
}
static void public_der_destroy(void *context)
{
    struct public_der_context *source = context;
    nvs_close(source->source.handle);
    pki_owned_free(source);
}
static int public_der_read(void *context, unsigned index, uint8_t **bytes,
                           size_t *size)
{
    struct pki_der_source *source =
                              &((struct public_der_context *)context)->source,
                          current;
    *bytes = NULL;
    *size = 0;
    if(pthread_mutex_trylock(&identity_lock))return -2;
    /* Renewal/reset cannot interleave metadata and part reads. A retired
     * pinned source fails without invalidating a newer valid derived cache. */
    int r = -1;
    if (!pki_der_cache_open(source->handle, &current) &&
        current.count == source->count &&
        !memcmp(current.hashes, source->hashes, sizeof source->hashes))
        r = pki_der_cache_read(source, index, bytes, size);
    pthread_mutex_unlock(&identity_lock);
    return r;
}
static struct pki_public_chain *
public_der_source(const struct pki_der_source *source, uint64_t generation)
{
    struct pki_public_chain *public = pki_owned_calloc(1, sizeof *public);
    struct public_der_context *copy = pki_owned_malloc(sizeof *copy);
    if (!public || !copy)
    {
        pki_owned_free(public);
        pki_owned_free(copy);
        return NULL;
    }
    copy->source = *source;
    copy->generation = generation;
    copy->certificate_epoch=pki_public_certificate_epoch();
    if (open_identity(&copy->source.handle) != ESP_OK)
    {
        pki_owned_free(copy);
        pki_owned_free(public);
        return NULL;
    }
    public->count = source->count;
    memcpy(public->hashes, source->hashes, sizeof public->hashes);
    public->context = copy;
    public->sizes=copy->source.sizes;
    public->metadata=public_der_metadata;
    public->read = public_der_read;
    public->destroy = public_der_destroy;
    public->load_trust = public_trust_load;
    return public;
}
static int load_native_certificate(nvs_handle_t h, uint8_t **pem, size_t *size,
                                   struct pki_der_source *source)
{
    static bool attempted;
    static uint8_t attempted_certificate[32];
    if (!pki_der_cache_open(h, source)) {
        (void)pki_der_cache_prepare_ranges(source);
        return 0;
    }
    if (load_certificate(h, "certificate", pem, size))
        return -1;
    uint8_t hash[32];
    if (wendy_pki_sha256(*pem,*size,hash) ||
        (attempted && !memcmp(hash,attempted_certificate,sizeof hash)))
        return 0;
    memcpy(attempted_certificate,hash,sizeof hash);
    attempted = true;
    /* A best-effort derived cache removes the full PEM copy from subsequent
     * handshakes. Storage pressure preserves the original parsing path. */
    if (pki_der_cache_build(h, *pem, *size) || pki_der_cache_open(h, source))
        return 0;
    free(*pem);
    *pem = NULL;
    *size = 0;
    (void)pki_der_cache_prepare_ranges(source);
    return 0;
}
#endif
void wendy_pki_builtin_trust(bool *ready, bool *tsa_ready)
{
    *ready = ROOT_SIZE(device) > 0 && ROOT_SIZE(https) > 0;
    *tsa_ready = ROOT_SIZE(tsa) > 0;
}
static esp_err_t identity_challenge(bool status_only, char nonce_hex[65], bool *enrolled)
{
    nvs_handle_t h;
    if (open_identity(&h) != ESP_OK)
        return ESP_FAIL;
    size_t size = 0;
    esp_err_t cert_status = nvs_get_blob(h, "certificate", NULL, &size);
    int64_t pending = 0;
    esp_err_t reset_status = nvs_get_i64(h, "reset_pending", &pending);
    if ((cert_status != ESP_OK && cert_status != ESP_ERR_NVS_NOT_FOUND) ||
        (reset_status != ESP_OK && reset_status != ESP_ERR_NVS_NOT_FOUND)) {
        nvs_close(h);
        return ESP_FAIL;
    }
    /* Incomplete reset is not a usable unprovisioned state. */
    *enrolled = (cert_status == ESP_OK && size > 0) || pending != 0;
    if (status_only)
    {
        nonce_hex[0] = 0;
        nvs_close(h);
        return ESP_OK;
    }
    uint8_t nonce[32];
    esp_fill_random(nonce, sizeof nonce);
    nonce[0] = (nonce[0] & 0x7f) | 1;
    esp_err_t r = nvs_set_blob(h, "nonce", nonce, sizeof nonce);
    if (r == ESP_OK)
        r = nvs_commit(h);
    nvs_close(h);
    if (r != ESP_OK)
        return r;
    for (int i = 0; i < 32; i++)
        snprintf(nonce_hex + i * 2, 3, "%02x", nonce[i]);
    return ESP_OK;
}
esp_err_t wendy_pki_challenge(bool status_only, char nonce_hex[65], bool *enrolled)
{
    /* NVS serializes its own accesses. Status must remain responsive while
     * cloud connection/issuance is waiting on the network. Physical commands
     * share the WendyCom dispatch task, so reset and challenges do not race. */
    return identity_challenge(status_only, nonce_hex, enrolled);
}

/* This marker survives interruption between clearing configuration and keys. */
static bool identity_use_allowed(void)
{
    if (identity_resetting) return false;
    nvs_handle_t h;
    if (open_identity(&h) != ESP_OK) return false;
    int64_t pending = 0;
    esp_err_t result = nvs_get_i64(h, "reset_pending", &pending);
    nvs_close(h);
    return result == ESP_ERR_NVS_NOT_FOUND || (result == ESP_OK && pending == 0);
}

esp_err_t wendy_pki_reset(const char *expected_device_id, const char *nonce_hex)
{
    if (!expected_device_id || !nonce_hex || strlen(nonce_hex) != 64 ||
        strcmp(expected_device_id, wendy_conf_get_device_id()))
        return ESP_ERR_INVALID_ARG;
    uint8_t provided[32];
    for (size_t i = 0; i < sizeof provided; i++) {
        unsigned byte = 0;
        for (size_t j = 0; j < 2; j++) {
            char c = nonce_hex[i * 2 + j];
            if (c >= '0' && c <= '9') byte = (byte << 4) | (c - '0');
            else if (c >= 'a' && c <= 'f') byte = (byte << 4) | (c - 'a' + 10);
            else return ESP_ERR_INVALID_ARG;
        }
        provided[i] = (uint8_t)byte;
    }
    pthread_mutex_lock(&identity_lock);
    nvs_handle_t h;
    esp_err_t result = open_identity(&h);
    if (result != ESP_OK) goto unlock;
    uint8_t expected[32];
    size_t size = sizeof expected;
    result = nvs_get_blob(h, "nonce", expected, &size);
    unsigned mismatch = 0;
    if (result != ESP_OK || size != sizeof expected) {
        result = ESP_ERR_INVALID_STATE;
        goto done;
    }
    for (size_t i = 0; i < size; i++) mismatch |= expected[i] ^ provided[i];
    if (mismatch) {
        result = ESP_ERR_INVALID_ARG;
        goto done;
    }
    identity_resetting = true;
    pki_public_certificate_changed();
    result = nvs_set_i64(h, "reset_pending", 1);
    if (result == ESP_OK) result = nvs_commit(h);
    if (result != ESP_OK) goto done;
    /* Never erase keys while the old bootstrap token can still be used. */
    result = wendy_conf_clear_enrollment();
    if (result != ESP_OK) goto done;
    const char *keys[] = {"key", "certificate", "pending", "lite_ca", "pending_ca",
                          "tenant", "device", "nonce"
        ,"net_der_meta","net_der_ranges","net_der_0","net_der_1","net_der_2","net_der_3",
        "net_der_4","net_der_5","net_der_6","net_der_7"
    };
    for (size_t i = 0; i < sizeof keys / sizeof keys[0]; i++) {
        result = nvs_erase_key(h, keys[i]);
        if (result == ESP_ERR_NVS_NOT_FOUND) result = ESP_OK;
        if (result != ESP_OK) goto done;
    }
    result = nvs_commit(h);
    if (result != ESP_OK) goto done;
    result = nvs_erase_key(h, "reset_pending");
    if (result == ESP_ERR_NVS_NOT_FOUND) result = ESP_OK;
    if (result == ESP_OK) result = nvs_commit(h);
    /* The signed clock floor intentionally survives local identity reset. */
done:
    nvs_close(h);
unlock:
    pthread_mutex_unlock(&identity_lock);
    erase(provided, sizeof provided);
    return result;
}

static int clock_floor(nvs_handle_t h, int64_t *out)
{
    if (boot_floor.failed) return -1;
    if (!boot_floor.loaded) {
        int64_t floor = 0;
        esp_err_t r = nvs_get_i64(h,"floor",&floor);
        if (r != ESP_OK && r != ESP_ERR_NVS_NOT_FOUND) return -1;
        boot_floor.high_water = floor;
        boot_floor.loaded = true;
    }
    *out = boot_floor.high_water;
    return 0;
}
static int set_floor(nvs_handle_t h, time_t value)
{
    int64_t floor;
    if (clock_floor(h,&floor) || value < floor) return -1;
    if (value > floor && !boot_floor.attempted) {
        boot_floor.attempted = true;
        if (nvs_set_i64(h,"floor",value) != ESP_OK || nvs_commit(h) != ESP_OK) {
            boot_floor.failed = true;
            return -1;
        }
    }
    boot_floor.high_water = value;
    time_t current = time(NULL);
    if (value < current)
        value = current;
    struct timeval tv = {.tv_sec = value};
    return settimeofday(&tv, NULL);
}
esp_err_t wendy_pki_sync_time(const char *server, const uint8_t *reply, size_t size,
                              bool *synchronized, int64_t *seconds)
{
    (void)server; (void)reply; (void)size;
    *synchronized = false; *seconds = 0;
    return ESP_ERR_NOT_SUPPORTED;
}
static int seed_clock(nvs_handle_t h, struct wendy_conf_span seed, struct wendy_conf_span roots)
{
    int64_t floor = 0;
    if (clock_floor(h,&floor)) return -1;
    if (seed.size)
    {
        uint8_t nonce[32];
        size_t n = sizeof nonce;
        time_t when;
        if (nvs_get_blob(h, "nonce", nonce, &n) == ESP_OK && n == sizeof nonce &&
            !wendy_pki_verify_time(seed.data, seed.size, nonce, roots.data,
                                   roots.size, floor, &when))
        {
            if (set_floor(h, when))
                return -1;
            if (nvs_erase_key(h, "nonce") != ESP_OK || nvs_commit(h) != ESP_OK)
                return -1;
            floor = when;
        }
    }
    if (floor <= 0)
        return -1;
    /* This historical floor is only sufficient to fetch a fresh signed time.
     * No enrollment credential or broker session is used until refresh_time succeeds. */
    return set_floor(h, floor);
}
/* Bounded radio bootstrap. The carrier is untrusted; only the existing TSA
 * signature, nonce and persistent floor authorize a clock update. */
static int mesh_raw(const struct wendy_pki_stream* stream, void* buffer, size_t size,
    bool writing, int64_t deadline)
{
    uint8_t* p = buffer;
    while (size) {
        if (wendy_pki_reset_in_progress() || esp_timer_get_time() >= deadline) return -1;
        ssize_t n = writing ? stream->write(stream->context, p, size)
                            : stream->read(stream->context, p, size);
        if (n > 0 && (size_t)n <= size) { p += n; size -= n; }
        else if ((n != -2 && n != -3) || stream->wait(stream->context, n == -3, deadline) < 0)
            return -1;
    }
    return 0;
}
static int mesh_time_exchange(const struct wendy_pki_stream* stream,
    const uint8_t* request, size_t size, uint8_t** response, size_t* response_size,
    const char magic[4])
{
    if (!size || size > 128) return -1;
    uint8_t header[8] = { 0, 0, 0, 0, 0, 0, 0, (uint8_t)size };
    memcpy(header,magic,4);
    int64_t deadline = esp_timer_get_time() + INT64_C(30000000);
    if (mesh_raw(stream, header, 8, true, deadline)
        || mesh_raw(stream, (void*)request, size, true, deadline)
        || mesh_raw(stream, header, 4, false, deadline)) return -1;
    size_t n = ((uint32_t)header[0] << 24) | ((uint32_t)header[1] << 16)
        | ((uint32_t)header[2] << 8) | header[3];
    if (!n || n > 65536) return -1;
    uint8_t* bytes = malloc(n);
    if (!bytes) return -1;
    if (mesh_raw(stream, bytes, n, false, deadline)) { free(bytes); return -1; }
    *response = bytes;
    *response_size = n;
    return 0;
}
#if CONFIG_WENDY_NET_PEER
static int mesh_time_serve(const struct wendy_pki_stream* stream, const char* url,
    struct wendy_conf_span roots,const char magic[4])
{
    uint8_t header[8], request[128], *response = NULL;
    size_t size = 0;
    int result = -1;
    int64_t deadline = esp_timer_get_time() + INT64_C(30000000);
    if (mesh_raw(stream, header, 8, false, deadline) || memcmp(header, magic, 4)
        || header[4] || header[5] || header[6] || !header[7] || header[7] > 128) return -1;
    if (mesh_raw(stream, request, header[7], false, deadline)
        || pki_http_post(url, "application/timestamp-query", NULL, request, header[7],
            NULL, 0, (struct wendy_conf_span){0}, roots, &response, &size)) goto done;
    if (!size || size > 65536) goto done;
    for (unsigned i = 0; i < 4; ++i) header[i] = size >> (24 - i * 8);
    result = mesh_raw(stream, header, 4, true, deadline)
        || mesh_raw(stream, response, size, true, deadline) ? -1 : 0;
done:
    free(response);
    return result;
}
#endif
static int refresh_time_source(nvs_handle_t h, const char *url,
                        const struct wendy_conf_enrollment_data *data,
                        const struct wendy_pki_stream* stream,const char magic[4])
{
    uint8_t nonce[32], request[128], *response = NULL;
    size_t response_size = 0;
    esp_fill_random(nonce, sizeof nonce);
    nonce[0] = (nonce[0] & 0x7f) | 1;
    size_t n = wendy_pki_time_request(request, nonce);
    if (!n)
        return -1;
    int64_t started = esp_timer_get_time();
    int exchanged = stream && magic ?
        mesh_time_exchange(stream,request,n,&response,&response_size,magic) :
        stream ? pki_http_post_stream(url,"application/timestamp-query",request,n,
            data->https_roots,stream,&response,&response_size) :
        pki_http_post(url,"application/timestamp-query",NULL,request,n,NULL,0,(struct wendy_conf_span){0},
            data->https_roots,&response,&response_size);
    if (exchanged)
        return -1;
    int64_t floor = 0;
    time_t when = 0;
    int result = -1;
    if (esp_timer_get_time() - started <= 30000000 &&
        wendy_conf_snapshot_current(data->generation) && !clock_floor(h,&floor) &&
        !wendy_pki_verify_time(response, response_size, nonce, data->tsa_roots.data,
                               data->tsa_roots.size, floor, &when))
        result = set_floor(h, when);
    if (!result) {
        mesh_verified_seconds = when;
        mesh_verified_monotonic_us = esp_timer_get_time();
        mesh_verified_generation = data->generation;
    }
    free(response);
    return result;
}
static int refresh_time_via(nvs_handle_t h,const char *url,
    const struct wendy_conf_enrollment_data *data,const struct wendy_pki_stream *stream)
{
    return refresh_time_source(h,url,data,stream,NULL);
}
#if CONFIG_WENDY_NET_PEER
static ssize_t time_recv(void *context,void *bytes,size_t size)
{
    int n=recv(*(int*)context,bytes,size,0);
    return n<0 && (errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR) ? -2 : n;
}
static ssize_t time_send(void *context,const void *bytes,size_t size)
{
    int n=send(*(int*)context,bytes,size,0);
    return n<0 && (errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR ||
                  errno==ENOMEM || errno==ENOBUFS) ? -3 : n;
}
static int time_wait(void *context,bool writing,int64_t deadline)
{
    int fd=*(int*)context;
    int64_t left=deadline-esp_timer_get_time();
    if (fd<0 || fd>=FD_SETSIZE || left<=0) return -1;
    fd_set set;FD_ZERO(&set);FD_SET(fd,&set);
    struct timeval timeout={.tv_sec=left/1000000,.tv_usec=left%1000000};
    return select(fd+1,writing ? NULL : &set,writing ? &set : NULL,NULL,&timeout)>0 ? 0 : -1;
}
#endif
#if CONFIG_WENDY_NET_NAN
static int refresh_time_peer(nvs_handle_t h,const char *url,
    const struct wendy_conf_enrollment_data *data,const char *host,unsigned port)
{
    if (!port || port>65535) return -1;
    char service[6];snprintf(service,sizeof service,"%u",port);
    struct addrinfo hints={.ai_family=AF_UNSPEC,.ai_socktype=SOCK_STREAM,.ai_flags=AI_NUMERICHOST},*address=NULL;
    int resolution=getaddrinfo(host,service,&hints,&address);
    if(resolution || !address){
        ESP_LOGW(TAG,"signed-time peer resolve failed: host=%s code=%d",host,resolution);
        return -1;
    }
    int fd=socket(address->ai_family,SOCK_STREAM,0),result=-1;
    if (fd<0){freeaddrinfo(address);return -1;}
    if (fd>=FD_SETSIZE || fcntl(fd,F_SETFL,O_NONBLOCK)<0) goto done;
    if (connect(fd,address->ai_addr,address->ai_addrlen)<0) {
        int error=0;socklen_t size=sizeof error;
        if (errno!=EINPROGRESS || time_wait(&fd,true,esp_timer_get_time()+INT64_C(5000000)) ||
            getsockopt(fd,SOL_SOCKET,SO_ERROR,&error,&size) || error){
            ESP_LOGW(TAG,"signed-time peer connect failed: host=%s errno=%d socket=%d",host,errno,error);
            goto done;
        }
    }
    struct wendy_pki_stream stream={.context=&fd,.read=time_recv,.write=time_send,.wait=time_wait};
    result=refresh_time_source(h,url,data,&stream,"WNT1");
done:
    close(fd);freeaddrinfo(address);return result;
}
esp_err_t wendy_pki_net_sync_time(const char *host,unsigned port)
{
    if (!host) return ESP_ERR_INVALID_ARG;
    pthread_mutex_lock(&identity_lock);
    WendyConfEnrollment cfg=WendyConfEnrollment_init_zero;
    struct wendy_conf_enrollment_data data={0};
    nvs_handle_t h=0;bool opened=false;esp_err_t result=ESP_FAIL;
    const char *stage="trust selection";
    if (!identity_use_allowed() || !wendy_conf_is_current() ||
        wendy_conf_copy_time_trust(&cfg,&data,true,false)!=ESP_OK ||
        select_time_trust(&cfg,&data,false) ||
        open_identity(&h)!=ESP_OK) goto done;
    opened=true;
    stage="clock floor";
    if(seed_clock(h,data.signed_time,data.tsa_roots))goto done;
    stage="peer timestamp exchange";
    if(refresh_time_peer(h,cfg.time_url,&data,host,port) || !wendy_conf_is_current() ||
        wendy_pki_reset_in_progress()) goto done;
    result=ESP_OK;
done:
    if(result!=ESP_OK)ESP_LOGW(TAG,"signed-time peer bootstrap failed at %s",stage);
    if (opened) nvs_close(h);
    free(data.storage);erase(cfg.token,sizeof cfg.token);
    pthread_mutex_unlock(&identity_lock);
    return result;
}
#endif
static int refresh_time(nvs_handle_t h, const char* url,
    const struct wendy_conf_enrollment_data* data)
{
    return refresh_time_via(h, url, data, NULL);
}
static int identity_key(nvs_handle_t h, const WendyConfEnrollment *cfg, uint8_t **key, size_t *size)
{
    char tenant[37], device[65];
    size_t tn = sizeof tenant, dn = sizeof device;
    esp_err_t t = nvs_get_str(h, "tenant", tenant, &tn), d = nvs_get_str(h, "device", device, &dn);
    if (t == ESP_OK || d == ESP_OK)
    {
        if (t != ESP_OK || d != ESP_OK || strcmp(tenant, cfg->tenant_id) ||
            strcmp(device, cfg->device_id))
            return -1;
        return load_blob(h, "key", key, size);
    }
    if (t != ESP_ERR_NVS_NOT_FOUND || d != ESP_ERR_NVS_NOT_FOUND)
        return -1;
    int result = -1;
    *key = malloc(256);
    if (!*key) goto done;
    int n = wendy_pki_generate_key_der(*key, 256);
    if (n <= 0) goto done;
    memmove(*key, *key+256-n, n);
    *size = n;
    if (nvs_set_blob(h, "key", *key, *size) != ESP_OK ||
        nvs_set_str(h, "tenant", cfg->tenant_id) != ESP_OK ||
        nvs_set_str(h, "device", cfg->device_id) != ESP_OK || nvs_commit(h) != ESP_OK) goto done;
    result = 0;
done:
    if (result && *key) { erase(*key, 256); free(*key); *key = NULL; }
    return result;
}
static char *make_csr(const uint8_t *key, size_t key_size, const char *device)
{
    mbedtls_pk_context k;
    mbedtls_x509write_csr csr;
    mbedtls_pk_init(&k); mbedtls_x509write_csr_init(&csr);
    char *pem = calloc(1, 4096), subject[80];
    // Device IDs are restricted by provisioning to this DN-safe alphabet.
    if (!pem || !device || !*device || strlen(device)>64 ||
        strspn(device, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.") != strlen(device)) goto fail;
    snprintf(subject, sizeof subject, "CN=%s", device);
    if (mbedtls_pk_parse_key(&k, key, key_size, NULL, 0) ||
        mbedtls_x509write_csr_set_subject_name(&csr, subject)) goto fail;
    mbedtls_x509write_csr_set_key(&csr, &k);
    mbedtls_x509write_csr_set_md_alg(&csr, MBEDTLS_MD_SHA256);
    if (mbedtls_x509write_csr_pem(&csr, (unsigned char *)pem, 4096)) goto fail;
    goto done;
fail:
    free(pem); pem = NULL;
done:
    mbedtls_x509write_csr_free(&csr); mbedtls_pk_free(&k);
    return pem;
}
static int issue(nvs_handle_t h, const WendyConfEnrollment *cfg,
                 const struct wendy_conf_enrollment_data *data, const uint8_t *key,
                 size_t key_size, struct wendy_conf_span old, const char *principal, struct wendy_conf_span *issued,
                 time_t *expires)
{
    char *csr = make_csr(key, key_size, cfg->device_id), *json = NULL;
    uint8_t *response = NULL;
    size_t response_size = 0;
    int result = -1;
    cJSON *body = NULL, *reply = NULL;
    char url[280];
    uint8_t *pending = NULL, *pending_authority = NULL;
    size_t pending_size = 0, pending_authority_size = 0;
    char *authority_header = NULL;
    uint8_t *authority_der=NULL,*certificate_der=NULL;size_t authority_size=0,der_size=0;
    const char *certificate = NULL;
    esp_err_t pending_status = nvs_get_blob(h, "pending", NULL, &pending_size);
    if (pending_status != ESP_ERR_NVS_NOT_FOUND)
    {
        /* Replay an authenticated response before trying to spend its token or
         * renewal predecessor again. A NUL blob marks a header omitted on renewal. */
        if (pending_status != ESP_OK || load_blob(h, "pending", &pending, &pending_size) ||
            load_blob(h, "pending_ca", &pending_authority, &pending_authority_size))
        {
            ESP_LOGE(TAG, "incomplete pending issuance; operator recovery required");
            goto done;
        }
        bool omitted_on_renewal = old.data && pending_authority_size == 1 && !pending_authority[0];
        if (!omitted_on_renewal &&
            (strlen((char *)pending_authority) != pending_authority_size ||
             wendy_pki_lite_authority_from_header((char *)pending_authority, &authority_der,&authority_size)))
        {
            ESP_LOGE(TAG, "pending issuance has no valid Lite operator authority");
            goto done;
        }
        certificate = (char *)pending;
        goto verify;
    }
    if (nvs_get_blob(h, "pending_ca", NULL, &pending_authority_size) != ESP_ERR_NVS_NOT_FOUND)
    {
        ESP_LOGE(TAG, "incomplete pending issuance; operator recovery required");
        goto done;
    }
    if (!csr || (!old.data && !cfg->token[0]))
        goto done;
    body = cJSON_CreateObject();
    if (!body || !cJSON_AddStringToObject(body, "csr", csr) ||
        !cJSON_AddStringToObject(body, "device_id", cfg->device_id) ||
        !cJSON_AddStringToObject(body, "tier", "C"))
        goto done;
    json = cJSON_PrintUnformatted(body);
    if (!json)
        goto done;
    free(csr); csr = NULL;
    cJSON_Delete(body); body = NULL;
    snprintf(url, sizeof url, "%s/%s", cfg->csr_url, old.data ? "renew" : "enroll");
    if (pki_http_post_enrollment(url, "application/json", old.data ? NULL : cfg->token,
                                 json, strlen(json), old.data ? key : NULL, old.data ? key_size : 0,
                                 old, data->https_roots, &response, &response_size,
                                 &authority_header))
        goto done;
    free(json); json = NULL;
    reply = cJSON_ParseWithLength((char *)response, response_size);
    /* cJSON owns its decoded strings; the raw HTTP response is no longer used. */
    free(response); response = NULL;
    if (!reply)
    {
        ESP_LOGE(TAG, "invalid issuance JSON (%zu bytes)", response_size);
        goto done;
    }
    cJSON *cert = cJSON_GetObjectItemCaseSensitive(reply, "certificate");
    if (!cJSON_IsString(cert) || !cert->valuestring)
    {
        ESP_LOGE(TAG, "issuance response has no certificate");
        goto done;
    }
    certificate = cert->valuestring;
    /* Keep the public response separate from the usable identity. A consumed
     * token or renewal predecessor cannot fetch it again after a failure.
     * Retain invalid or missing authority responses too, so retries fail closed
     * without attempting to spend that token a second time. */
    {
        static const uint8_t omitted_authority = 0;
        /* Attempt and commit both writes even if one fails. Either retained
         * piece prevents a retry from spending the credential again. */
        esp_err_t pending_saved = nvs_set_blob(h, "pending", certificate, strlen(certificate));
        esp_err_t authority_saved = authority_header ?
            nvs_set_blob(h, "pending_ca", authority_header, strlen(authority_header)) :
            old.data ? nvs_set_blob(h, "pending_ca", &omitted_authority, sizeof omitted_authority) :
                  nvs_erase_key(h, "pending_ca");
        esp_err_t committed = nvs_commit(h);
        if (pending_saved != ESP_OK || committed != ESP_OK ||
            (authority_saved != ESP_OK &&
             (authority_header || old.data || authority_saved != ESP_ERR_NVS_NOT_FOUND)))
        {
            ESP_LOGE(TAG, "could not retain pending issuance response");
            goto done;
        }
    }
    if (authority_header)
    {
        if (wendy_pki_lite_authority_from_header(authority_header, &authority_der,&authority_size))
        {
            ESP_LOGE(TAG, "issuance returned an invalid Lite operator authority");
            goto done;
        }
    }
    else if (!old.data)
    {
        ESP_LOGE(TAG, "initial enrollment has no Lite operator authority");
        goto done;
    }
verify:;
    size_t n = pending ? pending_size : strlen(certificate);
    if(wendy_cert_bundle_measure((const uint8_t*)certificate,n,&der_size))goto done;
    certificate_der=malloc(der_size);
    if(!certificate_der || wendy_cert_bundle_import((const uint8_t*)certificate,n,
                    certificate_der,der_size,&der_size))goto done;
    /* Keep only DER and the decoded authority through the next TLS request.
     * A pending replay also allocated a CSR before discovering its response. */
    free(csr);csr=NULL;
    free(authority_header);authority_header=NULL;
    free(pending_authority);pending_authority=NULL;
    free(pending);pending=NULL;
    cJSON_Delete(reply);reply=NULL;certificate=NULL;
    /* Fresh authenticated time must follow issuance; never relax notBefore. */
    if (refresh_time(h, cfg->time_url, data))
    {
        ESP_LOGE(TAG, "verified post-issuance time unavailable; response retained");
        goto done;
    }
    if (wendy_pki_verify_identity(certificate_der,der_size, data->device_roots.data,
                                  data->device_roots.size, key, key_size, principal, time(NULL),
                                  expires))
        goto done;
    /* Only an authenticated response with a valid identity may replace the
     * operator pin. Renewal without the header preserves the existing pin. */
    /* Every certificate installer retires derived metadata first, including
     * baseline issuance before native service activation in a later layer. */
    if(pki_der_cache_invalidate(h))goto done;
    esp_err_t saved = authority_der ?
        nvs_set_blob(h,"lite_ca",authority_der,authority_size) : ESP_OK;
    if (saved == ESP_OK)
        saved = nvs_set_blob(h,"certificate",certificate_der,der_size);
    if (saved == ESP_OK)
        saved = nvs_commit(h);
    if (saved != ESP_OK)
    {
        ESP_LOGE(TAG, "saving issued certificate: %s", esp_err_to_name(saved));
        goto done;
    }
    nvs_erase_key(h, "pending");
    nvs_erase_key(h, "pending_ca");
    nvs_commit(h);
    *issued=(struct wendy_conf_span){certificate_der,der_size};
    certificate_der=NULL;
    result = 0;
done:
    free(authority_der);
    free(certificate_der);
    free(authority_header);
    free(pending_authority);
    free(pending);
    free(csr);
    free(json);
    free(response);
    cJSON_Delete(body);
    cJSON_Delete(reply);
    return result;
}
/* Canonical lowercase 8-4-4-4-12 UUID, the only form tenant and device ids take. */
static int canonical_uuid(const char *id)
{
    if (strlen(id) != 36)
        return 0;
    for (int i = 0; i < 36; i++)
        if (i == 8 || i == 13 || i == 18 || i == 23)
        {
            if (id[i] != '-')
                return 0;
        }
        else if (!strchr("0123456789abcdef", id[i]))
            return 0;
    return 1;
}
static int valid_config(const WendyConfEnrollment *c)
{
    /* The device id is the device's one id (WDY-3919): the CLI-minted UUID in
     * the certificate's SAN, also its cloud asset id. */
    if (!canonical_uuid(c->tenant_id) || !canonical_uuid(c->device_id) || !c->broker_host[0] ||
        !c->broker_port || c->broker_port > 65535)
        return 0;
    char suffix[48];
    snprintf(suffix, sizeof suffix, "/v1/%s", c->tenant_id);
    size_t n = strlen(c->csr_url), s = strlen(suffix);
    return n > s && !strcmp(c->csr_url + n - s, suffix) && !strncmp(c->csr_url, "https://", 8) &&
           !strncmp(c->time_url, "https://", 8);
}
/* Device, timestamp and HTTPS roots come only from physical setup configuration
 * or the build. The separate Lite operator pin never replaces these roots. */
static int select_trust(const WendyConfEnrollment *cfg, struct wendy_conf_enrollment_data *data)
{
    if (!cfg->provision_trust)
    {
        if (data->device_roots.size || data->tsa_roots.size || data->https_roots.size) {
            ESP_LOGE(TAG, "Runtime CA bundles require explicit trust provisioning");
            return -1;
        }
        data->device_roots = (struct wendy_conf_span){wendy_pki_device_roots_start, ROOT_SIZE(device)};
        data->tsa_roots = (struct wendy_conf_span){wendy_pki_tsa_roots_start, ROOT_SIZE(tsa)};
        data->https_roots = (struct wendy_conf_span){wendy_pki_https_roots_start, ROOT_SIZE(https)};
    }
    const struct wendy_conf_span roots[] = {data->device_roots, data->tsa_roots, data->https_roots};
    const char *names[] = {"device", "timestamp", "HTTPS"};
    for (size_t i = 0; i < sizeof roots / sizeof roots[0]; i++) {
#if CONFIG_WENDY_NET_PEER
        int checked=i==0 ? check_device_roots(data) :
            wendy_pki_verify_roots(roots[i].data,roots[i].size);
#else
        int checked=wendy_pki_verify_roots(roots[i].data,roots[i].size);
#endif
        if (checked) {
            ESP_LOGE(TAG, "Invalid or missing %s CA bundle (%zu bytes); provision compatible trust roots over USB",
                     names[i], roots[i].size);
            return -1;
        }
    }
    return 0;
}
static int validate_config_and_trust(const WendyConfEnrollment *cfg,
                                   struct wendy_conf_enrollment_data *data)
{
    if (!valid_config(cfg)) {
        ESP_LOGE(TAG, "Invalid enrollment configuration; check tenant/device IDs, broker address/port, and HTTPS enrollment/time endpoints");
        return -1;
    }
    return select_trust(cfg, data);
}
#if CONFIG_WENDY_NET_PEER || CONFIG_WENDY_NET_NAN
static int select_time_trust(const WendyConfEnrollment *cfg,
    struct wendy_conf_enrollment_data *data,bool https)
{
    if (!valid_config(cfg)) return -1;
    if (!cfg->provision_trust) {
        if (data->device_roots.size || data->tsa_roots.size || data->https_roots.size) return -1;
        data->tsa_roots=(struct wendy_conf_span){wendy_pki_tsa_roots_start,ROOT_SIZE(tsa)};
        if (https) data->https_roots=(struct wendy_conf_span){wendy_pki_https_roots_start,ROOT_SIZE(https)};
    }
    return wendy_pki_verify_roots(data->tsa_roots.data,data->tsa_roots.size) ||
        (https && wendy_pki_verify_roots(data->https_roots.data,data->https_roots.size)) ? -1:0;
}
#endif

esp_err_t wendy_pki_validate_setup(const WendyConfEnrollment *cfg,
                                 const struct wendy_conf_enrollment_data *input)
{
    char unused[65];
    bool enrolled = true;
    if (wendy_pki_reset_in_progress() || wendy_conf_has_enrollment() ||
        wendy_pki_challenge(true, unused, &enrolled) != ESP_OK || enrolled ||
        !cfg->token[0] || strchr(cfg->token, '\r') || strchr(cfg->token, '\n') ||
        !input->signed_time.size)
        return ESP_ERR_INVALID_STATE;
    struct wendy_conf_enrollment_data data = *input;
    if (validate_config_and_trust(cfg, &data)) return ESP_ERR_INVALID_ARG;
    nvs_handle_t h;
    if (open_identity(&h) != ESP_OK) return ESP_FAIL;
    int64_t floor = 0;
    uint8_t nonce[32];
    size_t n = sizeof nonce;
    time_t verified = 0;
    esp_err_t e = nvs_get_i64(h, "floor", &floor);
    bool valid = (e == ESP_OK || e == ESP_ERR_NVS_NOT_FOUND) &&
        nvs_get_blob(h, "nonce", nonce, &n) == ESP_OK && n == sizeof nonce &&
        !wendy_pki_verify_time(data.signed_time.data, data.signed_time.size, nonce,
                              data.tsa_roots.data, data.tsa_roots.size, floor, &verified);
    nvs_close(h);
    erase(nonce, sizeof nonce);
    return valid ? ESP_OK : ESP_ERR_INVALID_ARG;
}

static esp_err_t connect_identity(wendy_pki_connection **connection)
{
    if (wendy_pki_crypto_init())
        return ESP_FAIL;
    WendyConfEnrollment cfg = WendyConfEnrollment_init_zero;
    struct wendy_conf_enrollment_data data;
    esp_err_t copy_result = wendy_conf_copy_enrollment(&cfg, &data);
    if (copy_result != ESP_OK)
    {
        erase(cfg.token, sizeof cfg.token);
        return copy_result;
    }
    if (validate_config_and_trust(&cfg, &data))
    {
        free(data.storage);
        erase(cfg.token, sizeof cfg.token);
        return ESP_ERR_INVALID_ARG;
    }
    nvs_handle_t h;
    if (open_identity(&h) != ESP_OK)
    {
        free(data.storage);
        erase(cfg.token, sizeof cfg.token);
        return ESP_FAIL;
    }
    uint8_t *key = NULL, *stored = NULL;
    size_t key_size = 0, stored_size = 0;
    struct wendy_conf_span fresh={0};
    esp_err_t result = ESP_FAIL;
    time_t expires = 0;
    char principal[160];
    snprintf(principal, sizeof principal, "spiffe://wendy.sh/tenant/%s/device/%s", cfg.tenant_id,
             cfg.device_id);
    if (seed_clock(h, data.signed_time, data.tsa_roots) || refresh_time(h, cfg.time_url, &data))
    {
        ESP_LOGE(TAG, "verified current PKI time unavailable; cloud connection held");
        goto done;
    }

    if (identity_key(h, &cfg, &key, &key_size))
    {
        ESP_LOGE(TAG, "identity key unavailable or enrollment binding changed");
        goto done;
    }
    esp_err_t cert_status = nvs_get_blob(h, "certificate", NULL, &stored_size);
    if (cert_status != ESP_ERR_NVS_NOT_FOUND &&
        (cert_status != ESP_OK || load_certificate(h, "certificate", &stored, &stored_size)))
        goto done;
    size_t pending_size = 0;
    esp_err_t pending_status = nvs_get_blob(h, "pending", NULL, &pending_size);
    if (pending_status != ESP_OK && pending_status != ESP_ERR_NVS_NOT_FOUND)
        goto done;
    bool have_pending = pending_status == ESP_OK;
    if (stored)
    {
        if (wendy_pki_verify_identity(stored, stored_size, data.device_roots.data,
                                      data.device_roots.size, key, key_size, principal, time(NULL),
                                      &expires) && !have_pending)
        {
            ESP_LOGE(TAG, "stored identity invalid or expired; operator recovery required");
            goto done;
        }
    }
    size_t authority_size = 0;
    esp_err_t authority_status = nvs_get_blob(h, "lite_ca", NULL, &authority_size);
    if (authority_status != ESP_OK && authority_status != ESP_ERR_NVS_NOT_FOUND)
        goto done;
    /* Existing installations predate the separately pinned Lite authority.
     * Renew their still-valid identity to obtain it through authenticated PKI. */
    bool have_authority = authority_status == ESP_OK && authority_size > 0 &&
                          authority_size <= PKI_MAX_RESPONSE;
    if (have_pending || !stored || !have_authority || expires - time(NULL) < 86400)
    {
        if (issue(h, &cfg, &data, key, key_size, (struct wendy_conf_span){stored,stored_size}, principal, &fresh, &expires))
        {
            /* Renewal can fail transiently. Recheck the stored identity after
             * the request, since it may have expired while the request ran. */
            if (!stored ||
                wendy_pki_verify_identity(stored, stored_size, data.device_roots.data,
                                          data.device_roots.size, key, key_size, principal,
                                          time(NULL), &expires))
            {
                ESP_LOGE(TAG, "pki-core issuance failed; no valid stored identity");
                goto done;
            }
            ESP_LOGW(TAG, "pki-core renewal failed; using still-valid stored identity");
        }
        else
            ESP_LOGI(TAG, "pki-core issued identity for %s", cfg.device_id);
    }
    ESP_LOGI(TAG, "connecting to broker %s:%u", cfg.broker_host, (unsigned)cfg.broker_port);
    if (pki_tls_connect(cfg.broker_host, cfg.broker_port, key, key_size,
                        fresh.data ? fresh : (struct wendy_conf_span){stored,stored_size}, data.https_roots, connection)) {
        ESP_LOGW(TAG, "broker TLS connection failed");
        goto done;
    }
    ESP_LOGI(TAG, "broker TLS authenticated; awaiting control handshake");
    result = ESP_OK;
done:
    if (key)
    {
        erase(key, key_size);
        free(key);
    }
    erase(cfg.token, sizeof cfg.token);
    free(data.storage);
    free(stored);
    free((void*)fresh.data);
    nvs_close(h);
    return result;
}


esp_err_t wendy_pki_connect(wendy_pki_connection **connection)
{
    pthread_mutex_lock(&identity_lock);
    esp_err_t result = identity_use_allowed() ? connect_identity(connection) : ESP_ERR_INVALID_STATE;
    pthread_mutex_unlock(&identity_lock);
    return result;
}

#if CONFIG_WENDY_NET_PEER
struct wendy_pki_agent_setup {
    wendy_pki_connection *connection;
    struct pki_der_source source;
    uint64_t generation;
    int64_t deadline;
    bool source_open,complete;
};
#endif
static esp_err_t accept_identity_peer(int fd, wendy_pki_connection **connection,
    const struct wendy_lite_trust *trust, bool allow_device,
    const struct wendy_pki_stream *stream,struct wendy_pki_agent_setup *async)
{
    const char *stage="crypto/configuration";
    int crypto_status = wendy_pki_crypto_init();
    WendyConfEnrollment cfg = WendyConfEnrollment_init_zero;
    struct wendy_conf_enrollment_data data = {0};
    nvs_handle_t h = 0;
    bool opened = false;
    uint8_t *key = NULL, *cert = NULL, *lite_ca = NULL;
    size_t key_size = 0, cert_size = 0, lite_ca_size = 0;
    time_t expires = 0;
    esp_err_t result = ESP_FAIL;
#if CONFIG_WENDY_NET_PEER
    struct pki_der_source local_source={0};
    struct pki_der_source *certificate_source=async ? &async->source:&local_source;
    uint8_t *input_reservation=NULL;
    uint8_t preparation_cookie=0;
    bool preparation_held=false;
    int64_t preparation_deadline=0;
#else
    (void)async;
#endif
#if CONFIG_WENDY_NET_PEER
    bool consume_native = !trust && (allow_device || stream);
#else
    bool consume_native = false;
#endif
    if (consume_native) {
        stage="trusted clock";
        bool recent=mesh_time_recent();
        if(async && !recent){result=ESP_ERR_TIMEOUT;goto done;}
        if (!recent) {
            /* A standalone enrolled device may have neither Cloud nor a mesh
             * attachment to initialize its clock. Obtain the same nonce-bound
             * proof before validating management certificates, then release
             * the time/HTTPS snapshot before loading the device identity. */
            if (wendy_conf_copy_enrollment(&cfg,&data)!=ESP_OK ||
                validate_config_and_trust(&cfg,&data) || open_identity(&h)!=ESP_OK) goto done;
            opened=true;
            if (seed_clock(h,data.signed_time,data.tsa_roots) ||
                refresh_time(h,cfg.time_url,&data) || !wendy_conf_is_current() ||
                wendy_pki_reset_in_progress()) goto done;
            free(data.storage);data=(struct wendy_conf_enrollment_data){0};
            nvs_close(h);opened=false;
        }
    }
#if CONFIG_WENDY_NET_PEER
    if(consume_native && !async){
        stage="native workspace admission";
        /* A readiness sample in the accept loop is not admission. The actor
         * may have claimed its input/workspace meanwhile. Wait here, after
         * optional HTTPS time bootstrap, before any native trust/input/key
         * preparation can overlap that live actor handshake. */
        preparation_deadline=esp_timer_get_time()+INT64_C(60000000);
        if(!pki_native_prepare_with_identity(&preparation_cookie,&identity_lock,preparation_deadline)){
            result=ESP_ERR_TIMEOUT;goto done;
        }
        preparation_held=true;
        /* Reset/configuration may have changed while identity was unlocked.
         * Do not start another HTTPS bootstrap while holding this workspace. */
        if(!identity_use_allowed() || !mesh_time_recent()){
            result=ESP_ERR_TIMEOUT;goto done;
        }
    }
#endif
    stage="trust snapshot";
    esp_err_t copied=consume_native ? wendy_conf_copy_device_trust(&cfg,&data) :
        wendy_conf_copy_enrollment(&cfg,&data);
    if (crypto_status || copied!=ESP_OK || !valid_config(&cfg)) goto done;
    if (consume_native) {
        if (!cfg.provision_trust)
            data.device_roots=(struct wendy_conf_span){wendy_pki_device_roots_start,ROOT_SIZE(device)};
        stage="CA validation";
#if CONFIG_WENDY_NET_PEER
        if(check_device_roots(&data))goto done;
#else
        if(wendy_pki_verify_roots(data.device_roots.data,data.device_roots.size))goto done;
#endif
#if CONFIG_WENDY_NET_PEER
        /* Root parsing needs temporary workspace too. Reserve only after that
         * verification, releasing the snapshot when roots are immutable flash
         * bytes; the smaller owned root copy is made below after the pin. */
        if(data.device_roots.data==wendy_pki_device_roots_start){
            struct wendy_conf_span roots=data.device_roots;
            uint64_t generation=data.generation;
            free(data.storage);
            data=(struct wendy_conf_enrollment_data){.device_roots=roots,.generation=generation};
        }
        input_reservation=pki_tls_input_take(NATIVE_TLS_INPUT_RESERVE);
#endif
    } else if (validate_config_and_trust(&cfg,&data)) goto done;
    stage="identity storage";
    if (open_identity(&h)!=ESP_OK) goto done;
    opened = true;
    char principal[160];
    snprintf(principal, sizeof principal, "spiffe://wendy.sh/tenant/%s/device/%s",
             cfg.tenant_id, cfg.device_id);
#if CONFIG_WENDY_NET_PEER
    if (consume_native) {
        /* The accepted native management session uses the system's trusted clock. Drop the
         * issuance/time-only snapshot before allocating the stored PEM chain. */
        size_t roots_size=data.device_roots.size;
        if (data.device_roots.data!=data.storage) {
            uint8_t *copy=malloc(roots_size+1);
            if (!copy) goto done;
            memcpy(copy,data.device_roots.data,roots_size);
            free(data.storage);data.storage=copy;
        }
        data.storage[roots_size]=0;
        data.device_roots=(struct wendy_conf_span){data.storage,roots_size};
        data.signed_time=data.tsa_roots=data.https_roots=(struct wendy_conf_span){0};
    }
#endif
    stage="stored key/certificate";
    if (identity_key(h, &cfg, &key, &key_size) ||
#if CONFIG_WENDY_NET_PEER
        (consume_native ? load_native_certificate(h,&cert,&cert_size,certificate_source) :
                       load_certificate(h,"certificate",&cert,&cert_size))) {
#else
        load_certificate(h,"certificate",&cert,&cert_size)) {
#endif
        ESP_LOGE(TAG,"accepted identity key/certificate allocation or storage read failed");
        goto done;
    }
    if (!consume_native && wendy_pki_verify_identity(cert, cert_size, data.device_roots.data,
            data.device_roots.size, key, key_size, principal, time(NULL), &expires)) goto done;
    /* An authorized relay stream can traverse a BLE mesh. Keep a bounded
     * setup window for the device chain, operator TLS and signed grant. Grant
     * and certificate expiry are still verified independently below. */
    /* Native agent TCP may arrive through BLE just like the app endpoint.
     * Certificate flights need a finite radio budget, independently of the
     * physical address used by an operator or loopback app relay. */
    int64_t deadline = esp_timer_get_time() +
        (trust || consume_native ? INT64_C(60000000) : INT64_C(15000000));
#if CONFIG_WENDY_NET_PEER
    if(preparation_held)deadline=preparation_deadline;
#endif
    stage="TLS/session setup";
    int accepted;
#if CONFIG_WENDY_NET_PEER
    if (consume_native) {
        /* Legacy PEM input uses ordinary TLS setup; only the indexed DER
         * constructor can take ownership of this preferred allocation. */
        if(!certificate_source->count){pki_tls_input_return(input_reservation,NATIVE_TLS_INPUT_RESERVE);input_reservation=NULL;pki_tls_input_discard_cached();}
        size_t roots_size=data.device_roots.size;
        struct pki_tls_owned_identity owned={.key=key,.key_size=key_size,
            .certificate=(char*)cert,.certificate_size=cert_size,.verify_at=time(NULL),
            .trust=data.storage,.trust_capacity=roots_size+1,
            .read_der=certificate_source->count ? pki_der_cache_read:NULL,
            .hash_der=certificate_source->count ? pki_der_cache_hash:NULL,
            .read_der_range=certificate_source->count ? pki_der_cache_read_range:NULL,
            .der_context=certificate_source,
            /* Operator paths are larger than device paths. Preserve their
             * input hole before local parsing to avoid a simultaneous 24KiB
             * old buffer and its larger Certificate-message replacement. */
            .input_reserve=NATIVE_TLS_INPUT_RESERVE,
            .input_reservation=input_reservation,.reserve_records_first=true,
            .preparation_owner=preparation_held ? &preparation_cookie:NULL};
        data.device_roots=(struct wendy_conf_span){data.storage,roots_size};
        data.storage=NULL;key=NULL;cert=NULL;input_reservation=NULL;
        accepted=async ? pki_tls_agent_begin(stream,cfg.tenant_id,cfg.device_id,&owned,
            data.device_roots,connection) : stream ? pki_tls_accept_owned_stream(stream,&owned,data.device_roots,
            cfg.tenant_id,cfg.device_id,connection,deadline) :
            pki_tls_accept_owned(&fd,&owned,data.device_roots,cfg.tenant_id,
            cfg.device_id,connection,deadline);
        if(async && !accepted){
            if(!wendy_conf_snapshot_current(data.generation) || wendy_pki_reset_in_progress()){
                wendy_pki_close(*connection);*connection=NULL;goto done;
            }
            async->generation=data.generation;async->deadline=deadline;
            if(certificate_source->count){async->source_open=true;opened=false;}
            result=ESP_OK;goto done;
        }
        if (!accepted) expires=(*connection)->device_expires;
    } else
#endif
    if (stream)
        accepted = pki_tls_accept_stream(stream, key, key_size, (struct wendy_conf_span){cert,cert_size},
                                        data.device_roots, cfg.tenant_id, connection, deadline);
    else if (trust)
    {
        if (load_certificate(h, "lite_ca", &lite_ca, &lite_ca_size))
        {
            ESP_LOGE(TAG, "Lite operator authority unavailable; authenticated renewal required");
            goto done;
        }
        accepted = pki_tls_accept_lite(fd, key, key_size, (struct wendy_conf_span){cert,cert_size},
                                      (struct wendy_conf_span){lite_ca, lite_ca_size},
                                      cfg.tenant_id, connection, deadline);
    }
    else if (allow_device)
        accepted = pki_tls_accept_lan(fd, key, key_size, (struct wendy_conf_span){cert,cert_size},
                                     data.device_roots, cfg.tenant_id, connection, deadline);
    else
        accepted = pki_tls_accept(fd, key, key_size, (struct wendy_conf_span){cert,cert_size},
                                 data.device_roots, cfg.tenant_id, connection, deadline);
    fd = -1; /* pki_tls_accept owns the socket, including failures. */
    if (!accepted) {
        (*connection)->device_expires = expires;
        if (!pki_limit_session(*connection,time(NULL),esp_timer_get_time()) &&
            (!trust || (!wendy_pki_sha256((uint8_t *)principal, strlen(principal), (*connection)->device_hash) &&
                       !pki_relay_grant(*connection, trust, deadline)))) {
            result = ESP_OK;
        } else {
            wendy_pki_close(*connection);
            *connection = NULL;
        }
    }
done:
    if(result!=ESP_OK)
        ESP_LOGW(TAG,"accepted identity failed at %s: free=%u largest=%u minimum=%u",
            stage,(unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT),
            (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT),
            (unsigned)heap_caps_get_minimum_free_size(MALLOC_CAP_8BIT));
    if (fd >= 0) close(fd);
#if CONFIG_WENDY_NET_PEER
    pki_tls_input_return(input_reservation,NATIVE_TLS_INPUT_RESERVE);
#endif
    if (key) { erase(key, key_size); free(key); }
    free(lite_ca);
    free(cert);
    free(data.storage);
    erase(cfg.token, sizeof cfg.token);
    if (opened) nvs_close(h);
#if CONFIG_WENDY_NET_PEER
    if(preparation_held)wendy_pki_handshake_release(&preparation_cookie);
#endif
    return result;
}

#if CONFIG_WENDY_NET_PEER
esp_err_t wendy_pki_agent_begin(const struct wendy_pki_stream *stream,struct wendy_pki_agent_setup **out)
{
    if(!out || !stream || !stream->read || !stream->write || !stream->wait)return ESP_ERR_INVALID_ARG;
    *out=NULL;
    if(pthread_mutex_trylock(&identity_lock))return ESP_ERR_TIMEOUT;
    struct wendy_pki_agent_setup *op=pki_owned_calloc(1,sizeof *op);
    esp_err_t r=op ? ESP_ERR_INVALID_STATE:ESP_ERR_NO_MEM;
    if(op && identity_use_allowed())r=accept_identity_peer(-1,&op->connection,NULL,true,stream,op);
    pthread_mutex_unlock(&identity_lock);
    if(r!=ESP_OK){wendy_pki_agent_dispose(op);return r;}
    *out=op;return ESP_OK;
}
int wendy_pki_agent_step(struct wendy_pki_agent_setup *op)
{
    if(!op || !op->connection || op->complete || wendy_pki_reset_in_progress() ||
       !wendy_conf_snapshot_current(op->generation) || esp_timer_get_time()>=op->deadline)return -1;
    int r=pki_tls_agent_advance(op->connection);
    if(!wendy_conf_snapshot_current(op->generation) || wendy_pki_reset_in_progress() ||
       esp_timer_get_time()>=op->deadline)return -1;
    if(!r){
        op->complete=true;
        /* The worker finished all certificate presentation before the actor
         * takes this context. Keep even read-handle teardown off the actor. */
        if(op->source_open){nvs_close(op->source.handle);op->source_open=false;}
    }
    return r;
}
wendy_pki_connection *wendy_pki_agent_take(struct wendy_pki_agent_setup *op,struct wendy_pki_agent_info *info)
{
    if(!op || !op->complete || !info || wendy_pki_reset_in_progress() ||
       !wendy_conf_snapshot_current(op->generation) || esp_timer_get_time()>=op->deadline ||
       esp_timer_get_time()>=op->connection->session_deadline_us)return NULL;
    *info=(struct wendy_pki_agent_info){.role=op->connection->peer_role,
        .config_generation=op->generation,.session_deadline_us=op->connection->session_deadline_us};
    wendy_pki_connection *connection=op->connection;op->connection=NULL;
    wendy_pki_agent_dispose(op);return connection;
}
void wendy_pki_agent_dispose(struct wendy_pki_agent_setup *op)
{
    if(!op)return;
    wendy_pki_close(op->connection);
    if(op->source_open)nvs_close(op->source.handle);
    pki_owned_free(op);
}
#endif

/* Read/verify effects are inert until called by an outer protocol worker. */
int wendy_pki_mesh_local_part(const struct wendy_pki_mesh_identity *clock,
    const uint8_t hash[32],size_t offset,uint8_t out[1024],size_t *total)
{
    if (!clock || !hash || !total) return -1;
    *total = 0;
    if (pthread_mutex_trylock(&identity_lock)) return -2;
    char tenant[37],device[65];
    int result = -1;
    nvs_handle_t handle;
    wendy_conf_enrollment_identity(tenant,device);
    if (identity_use_allowed() && wendy_conf_snapshot_current(clock->config_generation) &&
        !strcmp(tenant,clock->tenant) && !strcmp(device,clock->device) &&
        open_identity(&handle) == ESP_OK) {
        struct pki_der_source source;
        if (!pki_der_cache_open(handle,&source))
            result = pki_der_cache_part(&source,hash,offset,out,total);
        nvs_close(handle);
    }
    pthread_mutex_unlock(&identity_lock);
    return result;
}
bool wendy_pki_operator_snapshot_current(const struct wendy_pki_mesh_identity *clock)
{
    if(!clock || !wendy_conf_is_current() || wendy_pki_reset_in_progress() ||
       !wendy_conf_snapshot_current(clock->config_generation))return false;
    int64_t now=esp_timer_get_time();
    return now>=clock->verified_monotonic_us &&
        now-clock->verified_monotonic_us<INT64_C(300000000);
}
static int public_verify_snapshot(const struct wendy_pki_mesh_identity *clock,
    const uint8_t *const *der,const size_t *sizes,size_t count,
    void *peer,bool operator)
{
    if(!clock || !der || !sizes || !count || !peer ||
       !wendy_conf_is_current() || wendy_pki_reset_in_progress())return -1;
    int64_t monotonic=esp_timer_get_time();
    if(monotonic<clock->verified_monotonic_us ||
       monotonic-clock->verified_monotonic_us>=INT64_C(300000000))return -1;
    WendyConfEnrollment config=WendyConfEnrollment_init_zero;
    struct wendy_conf_enrollment_data trust={0};uint8_t hash[32];
    int result=-1;
    if(wendy_conf_copy_device_trust(&config,&trust)!=ESP_OK)goto done;
    if(!config.provision_trust)
        trust.device_roots=(struct wendy_conf_span){wendy_pki_device_roots_start,ROOT_SIZE(device)};
    if(trust.generation!=clock->config_generation || strcmp(config.tenant_id,clock->tenant) ||
       strcmp(config.device_id,clock->device) ||
       wendy_pki_sha256(trust.device_roots.data,trust.device_roots.size,hash) ||
       memcmp(hash,clock->trust_hash,32))goto done;
    time_t now=clock->verified_seconds+
        (monotonic-clock->verified_monotonic_us)/INT64_C(1000000);
    result=operator ? wendy_pki_operator_chain(der,sizes,count,trust.device_roots.data,
        trust.device_roots.size,clock->tenant,now,peer) :
        wendy_pki_mesh_chain(der,sizes,count,trust.device_roots.data,
        trust.device_roots.size,clock->tenant,now,peer);
    if(!wendy_conf_snapshot_current(trust.generation) || wendy_pki_reset_in_progress())result=-1;
done:
    free(trust.storage);return result;
}
int wendy_pki_mesh_verify_snapshot(const struct wendy_pki_mesh_identity *clock,
    const uint8_t *const *der,const size_t *sizes,size_t count,struct wendy_pki_mesh_peer *peer)
{return public_verify_snapshot(clock,der,sizes,count,peer,false);}
int wendy_pki_operator_verify_snapshot(const struct wendy_pki_mesh_identity *clock,
    const uint8_t *const *der,const size_t *sizes,size_t count,struct wendy_pki_operator_peer *peer)
{return public_verify_snapshot(clock,der,sizes,count,peer,true);}

#if CONFIG_WENDY_NET_PEER
struct wendy_pki_net_setup {
    wendy_pki_connection *connection;
    struct wendy_pki_mesh_identity identity;
    struct pki_der_source source;
    bool source_open,application,complete;
    char expected[37];
};
static esp_err_t mesh_connect(const char* host, unsigned port, const char* router,
    wendy_pki_connection** connection, struct wendy_pki_mesh_identity* identity,
    const struct wendy_pki_stream* stream, bool server, const char* protocol,
    int accepted_fd, char accepted_peer[37],struct wendy_pki_net_setup *async)
{
    bool incoming=accepted_fd>=0;

    bool application=protocol && !strcmp(protocol,"wendy-app-mesh-tls/1");
    bool native_stream=stream && protocol && (async || !strcmp(protocol,"wendy-local-mesh-ble/2"));
    if (!protocol || !connection || !identity || (!incoming && !native_stream && !router) ||
        (native_stream && (!stream->read || !stream->write || !stream->wait || !accepted_peer)) ||
        (incoming && (!server || !protocol || !accepted_peer)) ||
        (router && !wendy_identity_uuid((const unsigned char*)router,strlen(router)))) {
        if (accepted_fd>=0) close(accepted_fd);
        return ESP_ERR_INVALID_ARG;
    }
    if (accepted_peer) accepted_peer[0]=0;
    *connection = NULL;
    memset(identity, 0, sizeof *identity);
    if(async){if(pthread_mutex_trylock(&identity_lock))return ESP_ERR_TIMEOUT;}
    else pthread_mutex_lock(&identity_lock);
    WendyConfEnrollment cfg = WendyConfEnrollment_init_zero;
    struct wendy_conf_enrollment_data data = { 0 };
    nvs_handle_t h = 0;
    bool opened = false;
    uint8_t *key = NULL, *cert = NULL;
    size_t key_size = 0, cert_size = 0;
    esp_err_t result = ESP_FAIL;
    time_t expires = 0;
    const char *stage = "configuration";
#if CONFIG_WENDY_NET_PEER
    struct pki_der_source certificate_source={0};
    uint8_t *input_reservation=NULL;
    bool device_only=protocol && mesh_time_recent() &&
        wendy_conf_snapshot_current(mesh_verified_generation);
#endif
    if (!identity_use_allowed() || !wendy_conf_is_current() || wendy_pki_crypto_init()) goto done;
#if CONFIG_WENDY_NET_PEER
    if(device_only){
        /* Pin the final receive hole before a trust snapshot can divide the
         * largest free block. A warm connection needs only device roots;
         * the trusted clock remains bound to this exact configuration. */
        input_reservation=pki_tls_input_take(NATIVE_TLS_INPUT_RESERVE);
        esp_err_t snapshot=wendy_conf_copy_device_trust(&cfg,&data);
        /* The preferred receive hole is optional. Under concurrent app work
         * it must not prevent the mandatory, generation-bound trust snapshot.
         * Release it and retry that ordinary allocation before TLS setup. */
        if(snapshot==ESP_ERR_NO_MEM && input_reservation){
            pki_tls_input_return(input_reservation,NATIVE_TLS_INPUT_RESERVE);input_reservation=NULL;
            pki_tls_input_discard_cached();
            snapshot=wendy_conf_copy_device_trust(&cfg,&data);
        }
        if(snapshot!=ESP_OK || !valid_config(&cfg) ||
            data.generation!=mesh_verified_generation)goto done;
        if(!cfg.provision_trust)
            data.device_roots=(struct wendy_conf_span){wendy_pki_device_roots_start,ROOT_SIZE(device)};
        /* Prime the complete bundle-policy check before app flows occupy the
         * heap. Return the optional record hole while doing this once; later
         * management handshakes reuse only the exact generation/hash match.
         * TLS path/peer verification still runs for every connection. */
        uint8_t root_hash[32];
        if(!device_roots_checked(&data,root_hash)){
            pki_tls_input_return(input_reservation,NATIVE_TLS_INPUT_RESERVE);input_reservation=NULL;
            pki_tls_input_discard_cached();
            if(check_device_roots(&data))goto done;
            input_reservation=pki_tls_input_take(NATIVE_TLS_INPUT_RESERVE);
        }
    }else
#endif
    if(wendy_conf_copy_enrollment(&cfg,&data)!=ESP_OK || validate_config_and_trust(&cfg,&data))goto done;
    if (!wendy_identity_uuid((const unsigned char*)cfg.device_id, strlen(cfg.device_id))
        || (router && !strcmp(cfg.device_id,router)) || open_identity(&h) != ESP_OK)
        goto done;
    opened = true;
    stage = "trusted time";
    bool recent=mesh_time_recent() && mesh_verified_generation==data.generation;
    bool need_time=!recent;
#if CONFIG_WENDY_NET_PEER
    if(device_only && !recent)goto done; /* Retry through full cold bootstrap. */
#endif
    if(async && need_time)goto done; /* Outer driver bootstraps time separately. */
    if (need_time && (seed_clock(h, data.signed_time, data.tsa_roots)
        || refresh_time_via(h, cfg.time_url, &data, NULL)))
        goto done;
#if CONFIG_WENDY_NET_PEER
    if (protocol) {
        /* Signed time and both service trust bundles have served their purpose.
         * Keep only the exact device trust snapshot through this connection.
         * No configuration-cache pointer escapes its lock. */
        if (wendy_pki_sha256(data.device_roots.data, data.device_roots.size,
                             identity->trust_hash)) goto done;
        size_t roots_size = data.device_roots.size;
        size_t storage_size = data.signed_time.size + data.device_roots.size +
                              data.tsa_roots.size + data.https_roots.size;
        if(data.device_roots.data!=data.storage && !cfg.provision_trust){
            uint8_t *copy=malloc(roots_size+1);if(!copy)goto done;
            memcpy(copy,data.device_roots.data,roots_size);free(data.storage);data.storage=copy;
        }else if(!device_only){
            memmove(data.storage, data.device_roots.data, roots_size);
            uint8_t *compact = realloc(data.storage, roots_size+1);
            if (compact) data.storage = compact;
            else if (storage_size <= roots_size) goto done;
        }
        data.storage[roots_size] = 0;
        data.device_roots = (struct wendy_conf_span){data.storage, roots_size};
        data.signed_time = data.tsa_roots = data.https_roots = (struct wendy_conf_span){0};
    }
#endif
    char principal[106];
    snprintf(principal, sizeof principal, "spiffe://wendy.sh/tenant/%.36s/device/%.36s",
        cfg.tenant_id, cfg.device_id);
    stage = "stored key/certificate";
    if (identity_key(h, &cfg, &key, &key_size) ||
#if CONFIG_WENDY_NET_PEER
        (protocol ? load_native_certificate(h,&cert,&cert_size,&certificate_source) :
                    load_certificate(h,"certificate",&cert,&cert_size)))
#else
        load_certificate(h,"certificate",&cert,&cert_size))
#endif
        goto done;
    stage = "local certificate verification";
#if CONFIG_WENDY_NET_PEER
    if(protocol && !certificate_source.count){
        /* The optional DER cache may be absent. Preserve the complete PEM
         * constructor path instead of requiring an early DER reservation. */
        pki_tls_input_return(input_reservation,NATIVE_TLS_INPUT_RESERVE);input_reservation=NULL;
        pki_tls_input_discard_cached();
    }
#endif
    stage = "mesh TLS";
    int tls_result;
#if CONFIG_WENDY_NET_PEER
    if (protocol) {
        struct pki_tls_owned_identity owned = {.key=key, .key_size=key_size,
            .certificate=(char*)cert, .certificate_size=cert_size,
            .verify_at=mesh_verified_seconds+
                (esp_timer_get_time()-mesh_verified_monotonic_us)/1000000, .trust=data.storage,
            .trust_capacity=data.device_roots.size+1,
            /* Preserve a receive-buffer hole while placing identity objects,
             * then lend it to local-path verification before TLS starts.
             * Native carriers need this just as app sessions do when a
             * sibling encrypted carrier already occupies the heap. */
            .reserve_records_first=true,
            .input_reserve=NATIVE_TLS_INPUT_RESERVE,.input_reservation=input_reservation,
            .read_der=certificate_source.count ? pki_der_cache_read:NULL,
            .hash_der=certificate_source.count ? pki_der_cache_hash:NULL,
            .read_der_range=certificate_source.count ? pki_der_cache_read_range:NULL,
            .der_context=&certificate_source};
        if(certificate_source.count && !strcmp(protocol,"wendy-local-mesh-ble/2")) {
            owned.public_chain=public_der_source(&certificate_source,data.generation);
            if(!owned.public_chain)goto done;
        }
        if(async && certificate_source.count){
            async->source=certificate_source;
            owned.der_context=&async->source;
        }
        data.storage = NULL;
        key = NULL; cert = NULL;
        input_reservation=NULL;
        tls_result = async ? pki_tls_net_begin(stream,server,cfg.tenant_id,cfg.device_id,
                         &owned,data.device_roots,application,connection)
                     : incoming ? pki_tls_net_accept(&accepted_fd,cfg.tenant_id,cfg.device_id,
                         &owned,data.device_roots,protocol,connection)
                     : native_stream ? pki_tls_net_stream(stream,server,cfg.tenant_id,cfg.device_id,
                         router,&owned,data.device_roots,connection)
                     : pki_tls_net_connect(host,port,cfg.tenant_id,cfg.device_id,router,
                         &owned,data.device_roots,protocol,connection);
    } else tls_result=-1;
#endif
    if (tls_result)
        goto done;
    if (!expires) expires = (*connection)->device_expires;
    if (!async && (*connection)->operator_expires < expires)
        expires = (*connection)->operator_expires;
    if (!wendy_conf_is_current() || !wendy_conf_snapshot_current(data.generation) || wendy_pki_reset_in_progress()
        || esp_timer_get_time() - mesh_verified_monotonic_us >= INT64_C(300000000)
        || expires <= mesh_verified_seconds + 30
)
    {
        wendy_pki_close(*connection);
        *connection = NULL;
        goto done;
    }
    memcpy(identity->journal_trust_hash,cfg.provision_trust ?
        data.device_roots_source_hash : identity->trust_hash,32);
    stage = "route revision reservation";
    if (!application) {
        if (reserve_boot_revisions(h)) goto done;
    }
    memcpy(identity->tenant, cfg.tenant_id, 37);
    memcpy(identity->device, cfg.device_id, 37);
    memcpy(identity->peer, (*connection)->mesh_peer, sizeof identity->peer);
    identity->certificate_expires = expires;
    identity->verified_seconds = mesh_verified_seconds;
    identity->verified_monotonic_us = mesh_verified_monotonic_us;
    identity->config_generation = data.generation;
    (*connection)->device_expires = expires;
    int64_t lifetime = expires - mesh_verified_seconds;
    if (lifetime > 300)
        lifetime = 300;
    (*connection)->mesh_deadline_us = application ? 0 :
        mesh_verified_monotonic_us + lifetime * INT64_C(1000000);
    if (accepted_peer) memcpy(accepted_peer,(*connection)->mesh_peer,37);
#if CONFIG_WENDY_NET_PEER
    if(async && certificate_source.count){async->source_open=true;opened=false;}
#endif
    result = ESP_OK;
done:
    if (accepted_fd>=0) close(accepted_fd);
#if CONFIG_WENDY_NET_PEER
    pki_tls_input_return(input_reservation,NATIVE_TLS_INPUT_RESERVE);
#endif
    if (result != ESP_OK) ESP_LOGW(TAG, "native attachment failed at %s", stage);
    if (result != ESP_OK && *connection)
    {
        wendy_pki_close(*connection);
        *connection = NULL;
    }
    if (key)
    {
        erase(key, key_size);
        free(key);
    }
    free(cert);
    free(data.storage);
    erase(cfg.token, sizeof cfg.token);
    if (opened)
        nvs_close(h);
    pthread_mutex_unlock(&identity_lock);
    return result;
}
#if CONFIG_WENDY_NET_PEER
esp_err_t wendy_pki_net_begin(const struct wendy_pki_stream *stream,bool server,
    const char *expected,bool application,struct wendy_pki_net_setup **out)
{
    if(!out || !stream || !stream->read || !stream->write)return ESP_ERR_INVALID_ARG;
    *out=NULL;
    struct wendy_pki_net_setup *op=pki_owned_calloc(1,sizeof *op);if(!op)return ESP_ERR_NO_MEM;
    if(expected){if(strlen(expected)!=36){pki_owned_free(op);return ESP_ERR_INVALID_ARG;}memcpy(op->expected,expected,37);}
    op->application=application;char peer[37];
    esp_err_t r=mesh_connect(NULL,0,expected,&op->connection,&op->identity,stream,server,
        application ? "wendy-app-mesh-tls/1":"wendy-local-mesh-ble/2",-1,peer,op);
    if(r!=ESP_OK){wendy_pki_net_dispose(op);return r;}
    *out=op;return ESP_OK;
}
int wendy_pki_net_step(struct wendy_pki_net_setup *op)
{
    if(!op || op->complete || !op->connection)return -1;
    if(!wendy_conf_snapshot_current(op->identity.config_generation) || wendy_pki_reset_in_progress())return -1;
    int r=pki_tls_net_advance(op->connection,op->application,op->expected[0] ? op->expected:NULL);
    if(r)return r;
    wendy_pki_connection *c=op->connection;
    if(!wendy_conf_snapshot_current(op->identity.config_generation) || wendy_pki_reset_in_progress() ||
       c->operator_expires<=time(NULL) ||
       esp_timer_get_time()-op->identity.verified_monotonic_us>=INT64_C(300000000))return -1;
    if(c->operator_expires<op->identity.certificate_expires)op->identity.certificate_expires=c->operator_expires;
    memcpy(op->identity.peer,c->mesh_peer,37);
    c->device_expires=op->identity.certificate_expires;
    c->mesh_deadline_us=op->application ? 0:op->identity.verified_monotonic_us+INT64_C(300000000);
    op->complete=true;
    /* Certificate presentation has finished on this worker. Taking the ready
     * TLS context on the actor must never close even a read-only NVS handle. */
    if(op->source_open){nvs_close(op->source.handle);op->source_open=false;}
    return 0;
}
wendy_pki_connection *wendy_pki_net_take(struct wendy_pki_net_setup *op,struct wendy_pki_mesh_identity *identity)
{
    if(!op || !op->complete)return NULL;
    wendy_pki_connection *c=op->connection;op->connection=NULL;
    *identity=op->identity;wendy_pki_net_dispose(op);return c;
}
void wendy_pki_net_dispose(struct wendy_pki_net_setup *op)
{
    if(!op)return;
    wendy_pki_close(op->connection);
    if(op->source_open)nvs_close(op->source.handle);
    pki_owned_free(op);
}

esp_err_t wendy_pki_net_router_connect(const char *host,unsigned port,const char *peer,
    wendy_pki_connection **connection,struct wendy_pki_mesh_identity *identity)
{
    return mesh_connect(host,port,peer,connection,identity,NULL,false,"wendy-local-mesh-ble/2",-1,NULL,NULL);
}
esp_err_t wendy_pki_net_router_accept(int fd,wendy_pki_connection **connection,
    struct wendy_pki_mesh_identity *identity,char peer[37])
{
    return mesh_connect(NULL,0,NULL,connection,identity,NULL,true,"wendy-local-mesh-ble/2",fd,peer,NULL);
}
esp_err_t wendy_pki_net_router_stream(const struct wendy_pki_stream *stream,bool server,
    const char *expected_peer,wendy_pki_connection **connection,
    struct wendy_pki_mesh_identity *identity,char peer[37])
{
    if(!stream)return ESP_ERR_INVALID_ARG;
    return mesh_connect(NULL,0,expected_peer,connection,identity,stream,server,
                        "wendy-local-mesh-ble/2",-1,peer,NULL);
}
esp_err_t wendy_pki_app_accept(int fd,wendy_pki_connection **connection,
    struct wendy_pki_mesh_identity *identity,char peer[37])
{
    return mesh_connect(NULL,0,NULL,connection,identity,NULL,true,"wendy-app-mesh-tls/1",fd,peer,NULL);
}
esp_err_t wendy_pki_app_connect(const char *host,unsigned port,const char *peer,
    wendy_pki_connection **connection,struct wendy_pki_mesh_identity *identity)
{
    return mesh_connect(host,port,peer,connection,identity,NULL,false,"wendy-app-mesh-tls/1",-1,NULL,NULL);
}
#if CONFIG_WENDY_NET_PEER
int wendy_pki_net_time_status(void)
{
    if(pthread_mutex_trylock(&identity_lock))return -1;
    int recent=!wendy_pki_reset_in_progress() && mesh_time_recent();
    pthread_mutex_unlock(&identity_lock);return recent;
}
esp_err_t wendy_pki_net_bootstrap_time(const struct wendy_pki_stream *stream)
{
    pthread_mutex_lock(&identity_lock);
    WendyConfEnrollment config=WendyConfEnrollment_init_zero;
    struct wendy_conf_enrollment_data trust={0};nvs_handle_t handle=0;
    bool opened=false;esp_err_t result=ESP_FAIL;
    if(!identity_use_allowed() || !wendy_conf_is_current() ||
       wendy_conf_copy_time_trust(&config,&trust,true,true)!=ESP_OK ||
       select_time_trust(&config,&trust,true) || open_identity(&handle)!=ESP_OK)goto done;
    opened=true;
    if(seed_clock(handle,trust.signed_time,trust.tsa_roots) ||
       refresh_time_source(handle,config.time_url,&trust,stream,NULL) ||
       !wendy_conf_snapshot_current(trust.generation) || wendy_pki_reset_in_progress())goto done;
    result=ESP_OK;
done:
    if(opened)nvs_close(handle);
    free(trust.storage);erase(config.token,sizeof config.token);
    pthread_mutex_unlock(&identity_lock);return result;
}
/* A fixed-destination ciphertext relay, not an IP gateway. Both TLS and the
 * nonce-bound timestamp proof are verified by the requesting device. The
 * relay never receives a destination, key, token or plaintext HTTP request. */
esp_err_t wendy_pki_net_time_tunnel(const struct wendy_pki_stream *stream)
{
    struct tunnel {
        WendyConfEnrollment config;
        uint8_t up[512],down[512];
        char host[254];
    } *t=pki_owned_calloc(1,sizeof *t);
    if(!t)return ESP_ERR_NO_MEM;
    struct wendy_conf_enrollment_data trust={0};
    struct addrinfo hints={.ai_family=AF_UNSPEC,.ai_socktype=SOCK_STREAM},*addresses=NULL;
    int fd=-1;esp_err_t result=ESP_FAIL;uint64_t generation=0;
    if(!stream || !stream->read || !stream->write || !stream->wait ||
       !wendy_conf_is_current() || wendy_pki_reset_in_progress() ||
       wendy_conf_copy_time_trust(&t->config,&trust,false,false)!=ESP_OK)goto done;
    generation=trust.generation;free(trust.storage);trust.storage=NULL;
    struct http_parser_url url;http_parser_url_init(&url);
    const char *endpoint=t->config.time_url;
    if(strncmp(endpoint,"https://",8) || http_parser_parse_url(endpoint,strlen(endpoint),0,&url) ||
       !(url.field_set&(1<<UF_HOST)) || !url.field_data[UF_HOST].len ||
       url.field_data[UF_HOST].len>=sizeof t->host ||
       ((url.field_set&(1<<UF_PORT)) && url.port!=443))goto done;
    memcpy(t->host,endpoint+url.field_data[UF_HOST].off,url.field_data[UF_HOST].len);
    erase(t->config.token,sizeof t->config.token);
    int64_t deadline=esp_timer_get_time()+INT64_C(30000000);
    if(getaddrinfo(t->host,"443",&hints,&addresses) || !addresses)goto done;
    for(struct addrinfo *a=addresses;a;a=a->ai_next){
        fd=socket(a->ai_family,SOCK_STREAM,0);
        if(fd<0)continue;
        if(fd>=FD_SETSIZE || fcntl(fd,F_SETFL,O_NONBLOCK)<0){close(fd);fd=-1;continue;}
        if(connect(fd,a->ai_addr,a->ai_addrlen)<0){
            int error=0;socklen_t size=sizeof error;
            int64_t until=esp_timer_get_time()+INT64_C(5000000);
            if(until>deadline)until=deadline;
            if(errno!=EINPROGRESS || time_wait(&fd,true,until) ||
               getsockopt(fd,SOL_SOCKET,SO_ERROR,&error,&size) || error){close(fd);fd=-1;continue;}
        }
        break;
    }
    if(fd<0)goto done;
    size_t up_size=0,up_at=0,down_size=0,down_at=0;
    bool up_eof=false,down_eof=false;
    while(esp_timer_get_time()<deadline && wendy_conf_snapshot_current(generation) &&
          !wendy_pki_reset_in_progress()){
        bool progress=false;ssize_t n;
        if(!up_size && !up_eof){
            n=stream->read(stream->context,t->up,sizeof t->up);
            if(n>0){up_size=n;up_at=0;progress=true;}
            else if(!n)up_eof=true;else if(n!=-2 && n!=-3)goto done;
        }
        if(up_size){
            n=time_send(&fd,t->up+up_at,up_size);
            if(n>0){up_at+=n;up_size-=n;progress=true;}
            else if(n!=-2 && n!=-3)goto done;
        }
        if(!down_size && !down_eof){
            n=time_recv(&fd,t->down,sizeof t->down);
            if(n>0){down_size=n;down_at=0;progress=true;}
            else if(!n)down_eof=true;else if(n!=-2 && n!=-3)goto done;
        }
        if(down_size){
            n=stream->write(stream->context,t->down+down_at,down_size);
            if(n>0){down_at+=n;down_size-=n;progress=true;}
            else if(n!=-2 && n!=-3)goto done;
        }
        /* A BLE write only queues its final SDU. Authority EOF must not
         * release the channel while that SDU is waiting for credits. Keep
         * the pipe alive until the requester has read its complete HTTPS
         * response and closed; the same overall deadline bounds this wait. */
        if(up_eof && !up_size && !down_size){result=ESP_OK;break;}
        if(!progress)vTaskDelay(1);
    }
done:
    if(fd>=0)close(fd);
    if(addresses)freeaddrinfo(addresses);
    free(trust.storage);erase(t,sizeof *t);pki_owned_free(t);return result;
}
esp_err_t wendy_pki_time_query(const uint8_t *query,size_t size,uint8_t **reply,size_t *reply_size)
{
    if(!query || !size || size>128 || !reply || !reply_size)return ESP_ERR_INVALID_ARG;
    *reply=NULL;*reply_size=0;
    WendyConfEnrollment config=WendyConfEnrollment_init_zero;
    struct wendy_conf_enrollment_data trust={0};esp_err_t result=ESP_FAIL;
    if(wendy_conf_is_current() && !wendy_pki_reset_in_progress() &&
       wendy_conf_copy_time_trust(&config,&trust,false,true)==ESP_OK &&
       !select_time_trust(&config,&trust,true) &&
       !pki_http_post(config.time_url,"application/timestamp-query",NULL,query,size,NULL,0,(struct wendy_conf_span){0},
                      trust.https_roots,reply,reply_size) &&
       *reply_size && *reply_size<=65536 && wendy_conf_snapshot_current(trust.generation))result=ESP_OK;
    if(result!=ESP_OK){free(*reply);*reply=NULL;*reply_size=0;}
    free(trust.storage);erase(config.token,sizeof config.token);return result;
}
void wendy_pki_net_time_relay(int fd)
{
    WendyConfEnrollment config=WendyConfEnrollment_init_zero;
    struct wendy_conf_enrollment_data trust={0};
    if(fd>=0 && fd<FD_SETSIZE && fcntl(fd,F_SETFL,O_NONBLOCK)>=0 &&
       wendy_conf_is_current() && !wendy_pki_reset_in_progress() &&
       wendy_conf_copy_time_trust(&config,&trust,false,true)==ESP_OK &&
       !select_time_trust(&config,&trust,true)){
        struct wendy_pki_stream stream={.context=&fd,.read=time_recv,.write=time_send,.wait=time_wait};
        int result=mesh_time_serve(&stream,config.time_url,trust.https_roots,"WNT1");
        ESP_LOGI(TAG,"authenticated app time backend finished: result=%d",result);
    }
    free(trust.storage);erase(config.token,sizeof config.token);if(fd>=0)close(fd);
}
esp_err_t wendy_pki_net_time_reply(struct wendy_pki_mesh_identity *identity,const uint8_t nonce[32],
    const uint8_t *reply,size_t size,int64_t started)
{
    int64_t now=esp_timer_get_time();
    if(!identity || !nonce || !reply || !size || size>65536 || started<=0 ||
       now<started || now-started>INT64_C(30000000))return ESP_ERR_INVALID_ARG;
    pthread_mutex_lock(&identity_lock);
    WendyConfEnrollment config=WendyConfEnrollment_init_zero;
    struct wendy_conf_enrollment_data trust={0};
    nvs_handle_t handle=0;bool opened=false;esp_err_t result=ESP_FAIL;
    int64_t floor=0;time_t when=0;
    if(!identity_use_allowed() || !wendy_conf_is_current() ||
       wendy_conf_copy_time_trust(&config,&trust,false,false)!=ESP_OK ||
       trust.generation!=identity->config_generation ||
       strcmp(config.tenant_id,identity->tenant) || strcmp(config.device_id,identity->device) ||
       select_time_trust(&config,&trust,false) || open_identity(&handle)!=ESP_OK)goto done;
    opened=true;
    if(clock_floor(handle,&floor) ||
       wendy_pki_verify_time(reply,size,nonce,trust.tsa_roots.data,trust.tsa_roots.size,floor,&when) ||
       identity->certificate_expires<=when+30 || !wendy_conf_snapshot_current(trust.generation) ||
       esp_timer_get_time()-started>INT64_C(30000000) || set_floor(handle,when))goto done;
    mesh_verified_seconds=when;mesh_verified_monotonic_us=esp_timer_get_time();
    mesh_verified_generation=trust.generation;
    identity->verified_seconds=when;identity->verified_monotonic_us=mesh_verified_monotonic_us;
    result=ESP_OK;
done:
    if(opened)nvs_close(handle);
    free(trust.storage);erase(config.token,sizeof config.token);
    pthread_mutex_unlock(&identity_lock);return result;
}
#endif
esp_err_t wendy_pki_net_refresh_time(struct wendy_pki_mesh_identity *identity,
                                    const char *relay_host)
{
    if (!identity) return ESP_ERR_INVALID_ARG;
    pthread_mutex_lock(&identity_lock);
    WendyConfEnrollment cfg=WendyConfEnrollment_init_zero;
    struct wendy_conf_enrollment_data data={0};
    nvs_handle_t h=0;bool opened=false;esp_err_t result=ESP_FAIL;
    if (!identity_use_allowed() || !wendy_conf_is_current() ||
        wendy_conf_copy_time_trust(&cfg,&data,false,1)!=ESP_OK ||
        data.generation!=identity->config_generation ||
        select_time_trust(&cfg,&data,1) ||
        strcmp(cfg.tenant_id,identity->tenant) ||
        strcmp(cfg.device_id,identity->device) ||
        open_identity(&h)!=ESP_OK) goto done;
    opened=true;
    /* Two carriers usually renew together. Reuse a newer already verified
     * proof from this same generation rather than issuing duplicate HTTPS
     * requests; each carrier still applies its own original lifetime bound. */
    bool newer=mesh_time_recent() && mesh_verified_generation==data.generation &&
        mesh_verified_monotonic_us>identity->verified_monotonic_us;
    if(!newer){
    (void)relay_host;
    if (refresh_time(h,cfg.time_url,&data))goto done;
    }
    if(!wendy_conf_is_current() ||
        wendy_pki_reset_in_progress() || identity->certificate_expires<=mesh_verified_seconds+30)
        goto done;
    identity->verified_seconds=mesh_verified_seconds;
    identity->verified_monotonic_us=mesh_verified_monotonic_us;
    result=ESP_OK;
done:
    if (opened) nvs_close(h);
    free(data.storage);erase(cfg.token,sizeof cfg.token);
    pthread_mutex_unlock(&identity_lock);
    return result;
}
esp_err_t wendy_pki_net_apply_time(wendy_pki_connection *connection,
                                  const struct wendy_pki_mesh_identity *identity)
{
    if (!connection || !identity) return ESP_ERR_INVALID_ARG;
    /* The packet actor must never wait for a network handshake holding this
     * mutex. Its existing time/certificate limits keep running on a retry. */
    if (pthread_mutex_trylock(&identity_lock)) return ESP_ERR_TIMEOUT;
    int64_t now=esp_timer_get_time();
    esp_err_t result=ESP_FAIL;
    if (identity_use_allowed() && wendy_conf_snapshot_current(identity->config_generation) &&
        identity->config_generation==mesh_verified_generation &&
        identity->verified_seconds==mesh_verified_seconds &&
        identity->verified_monotonic_us==mesh_verified_monotonic_us &&
        !pki_net_apply_time(connection,identity,now)) result=ESP_OK;
    pthread_mutex_unlock(&identity_lock);
    return result;
}
esp_err_t wendy_pki_net_refresh(wendy_pki_connection *connection,
                               struct wendy_pki_mesh_identity *identity)
{
    if (!connection || !identity || !connection->mesh_deadline_us) return ESP_ERR_INVALID_ARG;
    const char *relay=NULL;
    struct wendy_pki_mesh_identity fresh=*identity;
    esp_err_t result=wendy_pki_net_refresh_time(&fresh,relay);
    if (result==ESP_OK) result=wendy_pki_net_apply_time(connection,&fresh);
    if (result==ESP_OK) *identity=fresh;
    return result;
}
#endif



#endif


static esp_err_t accept_peer(int fd, wendy_pki_connection **connection,
                              const struct wendy_lite_trust *trust, bool allow_device)
{
    pthread_mutex_lock(&identity_lock);
    esp_err_t result = ESP_ERR_INVALID_STATE;
    if (identity_use_allowed()) result = accept_identity_peer(fd, connection, trust, allow_device, NULL,NULL);
    else close(fd);
    pthread_mutex_unlock(&identity_lock);
    return result;
}

esp_err_t wendy_pki_accept(int fd, wendy_pki_connection **connection)
{
    return accept_peer(fd, connection, NULL, false);
}

esp_err_t wendy_pki_accept_stream(const struct wendy_pki_stream *stream,
                                wendy_pki_connection **connection)
{
    if (connection) *connection = NULL;
    if (!stream || !stream->read || !stream->write || !stream->wait || !connection)
        return ESP_ERR_INVALID_ARG;
    pthread_mutex_lock(&identity_lock);
    esp_err_t result = ESP_ERR_INVALID_STATE;
    if (identity_use_allowed())
        result = accept_identity_peer(-1, connection, NULL, false, stream,NULL);
    pthread_mutex_unlock(&identity_lock);
    return result;
}
esp_err_t wendy_pki_accept_lan(int fd, wendy_pki_connection **connection)
{
    return accept_peer(fd, connection, NULL, true);
}
esp_err_t wendy_pki_accept_relay(int fd, const struct wendy_lite_trust *trust,
                                  wendy_pki_connection **connection)
{
    if (!trust) { close(fd); return ESP_ERR_INVALID_ARG; }
    return accept_peer(fd, connection, trust, false);
}
