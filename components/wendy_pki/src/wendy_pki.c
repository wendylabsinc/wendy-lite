#include "cJSON.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "wendy_conf.h"
#include "wendy_pki_internal.h"
#include "wendy_peer_identity.h"
#include <unistd.h>
#include "wendy_pki_verify.h"
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
/* Historical NVS time is never a lease clock. Only a fresh nonce-bound reply
 * establishes this boot's monotonic anchor, under identity_lock. */
static time_t mesh_verified_seconds;
static int64_t mesh_verified_monotonic_us;
static pthread_once_t identity_once = PTHREAD_ONCE_INIT;
static esp_err_t identity_ready = ESP_FAIL;
/* Serialize issuance, status, and recovery so an in-flight enrollment cannot
 * restore a key or certificate after reset has erased it. */
static pthread_mutex_t identity_lock = PTHREAD_MUTEX_INITIALIZER;
static atomic_bool identity_resetting;
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
    result = nvs_set_i64(h, "reset_pending", 1);
    if (result == ESP_OK) result = nvs_commit(h);
    if (result != ESP_OK) goto done;
    /* Never erase keys while the old bootstrap token can still be used. */
    result = wendy_conf_clear_enrollment();
    if (result != ESP_OK) goto done;
    const char *keys[] = {"key", "certificate", "pending", "lite_ca", "pending_ca",
                          "tenant", "device", "nonce"};
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

static int set_floor(nvs_handle_t h, time_t value)
{
    int64_t floor = 0;
    esp_err_t r = nvs_get_i64(h, "floor", &floor);
    if (r != ESP_OK && r != ESP_ERR_NVS_NOT_FOUND)
        return -1;
    if (value < floor)
        return -1;
    if (value > floor && (nvs_set_i64(h, "floor", value) != ESP_OK || nvs_commit(h) != ESP_OK))
        return -1;
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
    esp_err_t e = nvs_get_i64(h, "floor", &floor);
    if (e != ESP_OK && e != ESP_ERR_NVS_NOT_FOUND)
        return -1;
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
    const uint8_t* request, size_t size, uint8_t** response, size_t* response_size)
{
    if (!size || size > 128) return -1;
    uint8_t header[8] = { 'W', 'M', 'T', '3', 0, 0, 0, (uint8_t)size };
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
#if CONFIG_WENDY_MESH_LEAF
static int mesh_time_serve(const struct wendy_pki_stream* stream, const char* url,
    struct wendy_conf_span roots)
{
    uint8_t header[8], request[128], *response = NULL;
    size_t size = 0;
    int result = -1;
    int64_t deadline = esp_timer_get_time() + INT64_C(30000000);
    if (mesh_raw(stream, header, 8, false, deadline) || memcmp(header, "WMT3", 4)
        || header[4] || header[5] || header[6] || !header[7] || header[7] > 128) return -1;
    if (mesh_raw(stream, request, header[7], false, deadline)
        || pki_http_post(url, "application/timestamp-query", NULL, request, header[7],
            NULL, 0, NULL, roots, &response, &size)) goto done;
    if (!size || size > 65536) goto done;
    for (unsigned i = 0; i < 4; ++i) header[i] = size >> (24 - i * 8);
    result = mesh_raw(stream, header, 4, true, deadline)
        || mesh_raw(stream, response, size, true, deadline) ? -1 : 0;
done:
    free(response);
    return result;
}
#endif
static int refresh_time_via(nvs_handle_t h, const char *url,
                        const struct wendy_conf_enrollment_data *data,
                        const struct wendy_pki_stream* stream)
{
    uint8_t nonce[32], request[128], *response = NULL;
    size_t response_size = 0;
    esp_fill_random(nonce, sizeof nonce);
    nonce[0] = (nonce[0] & 0x7f) | 1;
    size_t n = wendy_pki_time_request(request, nonce);
    if (!n)
        return -1;
    int64_t started = esp_timer_get_time();
    if (stream ? mesh_time_exchange(stream, request, n, &response, &response_size)
               : pki_http_post(url, "application/timestamp-query", NULL, request, n, NULL, 0, NULL,
                      data->https_roots, &response, &response_size))
        return -1;
    int64_t floor = 0;
    time_t when = 0;
    int result = -1;
    if (esp_timer_get_time() - started <= 30000000 && nvs_get_i64(h, "floor", &floor) == ESP_OK &&
        !wendy_pki_verify_time(response, response_size, nonce, data->tsa_roots.data,
                               data->tsa_roots.size, floor, &when))
        result = set_floor(h, when);
    else
        ESP_LOGE(TAG, "signed time response rejected");
    if (!result) {
        mesh_verified_seconds = when;
        mesh_verified_monotonic_us = esp_timer_get_time();
    }
    free(response);
    return result;
}
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
                 size_t key_size, const char *old, const char *principal, char **issued,
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
    char *authority_header = NULL, *authority_pem = NULL;
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
        bool omitted_on_renewal = old && pending_authority_size == 1 && !pending_authority[0];
        if (!omitted_on_renewal &&
            (strlen((char *)pending_authority) != pending_authority_size ||
             wendy_pki_lite_authority_from_header((char *)pending_authority, &authority_pem)))
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
    if (!csr || (!old && !cfg->token[0]))
        goto done;
    body = cJSON_CreateObject();
    if (!body || !cJSON_AddStringToObject(body, "csr", csr) ||
        !cJSON_AddStringToObject(body, "device_id", cfg->device_id) ||
        !cJSON_AddStringToObject(body, "tier", "C"))
        goto done;
    json = cJSON_PrintUnformatted(body);
    if (!json)
        goto done;
    snprintf(url, sizeof url, "%s/%s", cfg->csr_url, old ? "renew" : "enroll");
    if (pki_http_post_enrollment(url, "application/json", old ? NULL : cfg->token,
                                 json, strlen(json), old ? key : NULL, old ? key_size : 0,
                                 old, data->https_roots, &response, &response_size,
                                 &authority_header))
        goto done;
    /* Release request and response buffers before the post-issuance time
     * request. Boards without PSRAM cannot hold both responses at once. */
    free(csr); csr = NULL;
    free(json); json = NULL;
    cJSON_Delete(body); body = NULL;
    reply = cJSON_ParseWithLength((char *)response, response_size);
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
            old ? nvs_set_blob(h, "pending_ca", &omitted_authority, sizeof omitted_authority) :
                  nvs_erase_key(h, "pending_ca");
        esp_err_t committed = nvs_commit(h);
        if (pending_saved != ESP_OK || committed != ESP_OK ||
            (authority_saved != ESP_OK &&
             (authority_header || old || authority_saved != ESP_ERR_NVS_NOT_FOUND)))
        {
            ESP_LOGE(TAG, "could not retain pending issuance response");
            goto done;
        }
    }
    if (authority_header)
    {
        if (wendy_pki_lite_authority_from_header(authority_header, &authority_pem))
        {
            ESP_LOGE(TAG, "issuance returned an invalid Lite operator authority");
            goto done;
        }
    }
    else if (!old)
    {
        ESP_LOGE(TAG, "initial enrollment has no Lite operator authority");
        goto done;
    }
verify:
    /* The pre-request timestamp can lag issuance after network and signature
     * verification work. Obtain authenticated time generated after the response
     * instead of relaxing notBefore for a freshly minted identity. */
    if (refresh_time(h, cfg->time_url, data))
    {
        ESP_LOGE(TAG, "verified post-issuance time unavailable; response retained");
        goto done;
    }
    size_t n = pending ? pending_size : strlen(certificate);
    if (wendy_pki_verify_identity((uint8_t *)certificate, n, data->device_roots.data,
                                  data->device_roots.size, key, key_size, principal, time(NULL),
                                  expires))
        goto done;
    /* Only an authenticated response with a valid identity may replace the
     * operator pin. Renewal without the header preserves the existing pin. */
    esp_err_t saved = authority_pem ?
        nvs_set_blob(h, "lite_ca", authority_pem, strlen(authority_pem)) : ESP_OK;
    if (saved == ESP_OK)
        saved = nvs_set_blob(h, "certificate", certificate, n);
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
    *issued = strdup(certificate);
    if (!*issued)
        goto done;
    result = 0;
done:
    free(authority_pem);
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
/* Device, timestamp and HTTPS roots come only from USB-authorized configuration
 * or the build. The separate Lite operator pin never replaces these roots. */
static int select_trust(const WendyConfEnrollment *cfg, struct wendy_conf_enrollment_data *data)
{
    if (!cfg->provision_trust)
    {
        if (data->device_roots.size || data->tsa_roots.size || data->https_roots.size) {
            ESP_LOGE(TAG, "Runtime CA bundles require USB trust provisioning");
            return -1;
        }
        data->device_roots = (struct wendy_conf_span){wendy_pki_device_roots_start, ROOT_SIZE(device)};
        data->tsa_roots = (struct wendy_conf_span){wendy_pki_tsa_roots_start, ROOT_SIZE(tsa)};
        data->https_roots = (struct wendy_conf_span){wendy_pki_https_roots_start, ROOT_SIZE(https)};
    }
    const struct wendy_conf_span roots[] = {data->device_roots, data->tsa_roots, data->https_roots};
    const char *names[] = {"device", "timestamp", "HTTPS"};
    for (size_t i = 0; i < sizeof roots / sizeof roots[0]; i++) {
        if (wendy_pki_verify_roots(roots[i].data, roots[i].size)) {
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
    char *fresh = NULL;
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
        (cert_status != ESP_OK || load_blob(h, "certificate", &stored, &stored_size)))
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
        if (issue(h, &cfg, &data, key, key_size, (char *)stored, principal, &fresh, &expires))
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
                        fresh ? fresh : (char *)stored, data.https_roots, connection)) {
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
    free(fresh);
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

static esp_err_t accept_identity_peer(int fd, wendy_pki_connection **connection,
    const struct wendy_lite_trust *trust, bool allow_device,
    const struct wendy_pki_stream *stream)
{
    int crypto_status = wendy_pki_crypto_init();
    WendyConfEnrollment cfg = WendyConfEnrollment_init_zero;
    struct wendy_conf_enrollment_data data = {0};
    nvs_handle_t h = 0;
    bool opened = false;
    uint8_t *key = NULL, *cert = NULL, *lite_ca = NULL;
    size_t key_size = 0, cert_size = 0, lite_ca_size = 0;
    time_t expires;
    esp_err_t result = ESP_FAIL;
    if (crypto_status || wendy_conf_copy_enrollment(&cfg, &data) != ESP_OK ||
        validate_config_and_trust(&cfg, &data) || open_identity(&h) != ESP_OK)
        goto done;
    opened = true;
    char principal[160];
    snprintf(principal, sizeof principal, "spiffe://wendy.sh/tenant/%s/device/%s",
             cfg.tenant_id, cfg.device_id);
    if (identity_key(h, &cfg, &key, &key_size) ||
        load_blob(h, "certificate", &cert, &cert_size) ||
        wendy_pki_verify_identity(cert, cert_size, data.device_roots.data,
            data.device_roots.size, key, key_size, principal, time(NULL), &expires))
        goto done;
    /* An authorized relay stream can traverse a BLE mesh. Keep a bounded
     * setup window for the device chain, operator TLS and signed grant. Grant
     * and certificate expiry are still verified independently below. */
    int64_t deadline = esp_timer_get_time() + (trust ? INT64_C(60000000) : INT64_C(15000000));
    int accepted;
    if (stream)
        accepted = pki_tls_accept_stream(stream, key, key_size, (char *)cert,
                                        data.device_roots, cfg.tenant_id, connection, deadline);
    else if (trust)
    {
        if (load_blob(h, "lite_ca", &lite_ca, &lite_ca_size))
        {
            ESP_LOGE(TAG, "Lite operator authority unavailable; authenticated renewal required");
            goto done;
        }
        accepted = pki_tls_accept_lite(fd, key, key_size, (char *)cert,
                                      (struct wendy_conf_span){lite_ca, lite_ca_size},
                                      cfg.tenant_id, connection, deadline);
    }
    else if (allow_device)
        accepted = pki_tls_accept_lan(fd, key, key_size, (char *)cert,
                                     data.device_roots, cfg.tenant_id, connection, deadline);
    else
        accepted = pki_tls_accept(fd, key, key_size, (char *)cert,
                                 data.device_roots, cfg.tenant_id, connection, deadline);
    fd = -1; /* pki_tls_accept owns the socket, including failures. */
    if (!accepted) {
        (*connection)->device_expires = expires;
        if (!trust || (!wendy_pki_sha256((uint8_t *)principal, strlen(principal), (*connection)->device_hash) &&
                       !pki_relay_grant(*connection, trust, deadline))) {
            result = ESP_OK;
        } else {
            wendy_pki_close(*connection);
            *connection = NULL;
        }
    }
done:
    if (fd >= 0) close(fd);
    if (key) { erase(key, key_size); free(key); }
    free(lite_ca);
    free(cert);
    free(data.storage);
    erase(cfg.token, sizeof cfg.token);
    if (opened) nvs_close(h);
    return result;
}

#if CONFIG_WENDY_MESH_LEAF
static esp_err_t mesh_connect(const char* host, unsigned port, const char* router,
    wendy_pki_connection** connection, struct wendy_pki_mesh_identity* identity,
    const struct wendy_pki_stream* stream, bool server, bool discover_peer)
{
    if (!connection || !identity
        || (discover_peer ? (!stream || server || router)
            : (!router || !wendy_identity_uuid((const unsigned char*)router, strlen(router)))))
        return ESP_ERR_INVALID_ARG;
    *connection = NULL;
    memset(identity, 0, sizeof *identity);
    pthread_mutex_lock(&identity_lock);
    WendyConfEnrollment cfg = WendyConfEnrollment_init_zero;
    struct wendy_conf_enrollment_data data = { 0 };
    nvs_handle_t h = 0;
    bool opened = false;
    uint8_t *key = NULL, *cert = NULL;
    size_t key_size = 0, cert_size = 0;
    esp_err_t result = ESP_FAIL;
    time_t expires = 0;
    if (!identity_use_allowed() || !wendy_conf_is_current() || wendy_pki_crypto_init()
        || wendy_conf_copy_enrollment(&cfg, &data) != ESP_OK
        || validate_config_and_trust(&cfg, &data)
        || !wendy_identity_uuid((const unsigned char*)cfg.device_id, strlen(cfg.device_id))
        || (router && !strcmp(cfg.device_id, router)) || open_identity(&h) != ESP_OK)
        goto done;
    opened = true;
    if (seed_clock(h, data.signed_time, data.tsa_roots)
        || (stream && server && mesh_time_serve(stream, cfg.time_url, data.https_roots))
        || refresh_time_via(h, cfg.time_url, &data, server ? NULL : stream))
        goto done;
    char principal[106];
    snprintf(principal, sizeof principal, "spiffe://wendy.sh/tenant/%.36s/device/%.36s",
        cfg.tenant_id, cfg.device_id);
    if (identity_key(h, &cfg, &key, &key_size) || load_blob(h, "certificate", &cert, &cert_size)
        || wendy_pki_verify_identity(cert, cert_size, data.device_roots.data,
            data.device_roots.size, key, key_size, principal, mesh_verified_seconds, &expires))
        goto done;
    if (stream ? pki_tls_mesh_stream(stream, server, cfg.tenant_id, cfg.device_id, router,
                     key, key_size, (const char*)cert, data.device_roots, connection)
               : pki_tls_mesh_connect(host, port, cfg.tenant_id, cfg.device_id, router, key, key_size,
                     (const char*)cert, data.device_roots, connection))
        goto done;
    if ((*connection)->operator_expires < expires)
        expires = (*connection)->operator_expires;
    if (!wendy_conf_is_current() || wendy_pki_reset_in_progress()
        || esp_timer_get_time() - mesh_verified_monotonic_us >= INT64_C(300000000)
        || expires <= mesh_verified_seconds + 30
        || wendy_pki_sha256(data.device_roots.data, data.device_roots.size, identity->trust_hash))
    {
        wendy_pki_close(*connection);
        *connection = NULL;
        goto done;
    }
    uint64_t reserved = 0;
    size_t reserved_size = sizeof reserved;
    esp_err_t status = nvs_get_blob(h, "mesh_revision", &reserved, &reserved_size);
    if ((status != ESP_ERR_NVS_NOT_FOUND && (status != ESP_OK || reserved_size != sizeof reserved))
        || reserved > UINT64_MAX - 1025)
        goto done;
    uint64_t next = reserved + 1024;
    if (nvs_set_blob(h, "mesh_revision", &next, sizeof next) != ESP_OK || nvs_commit(h) != ESP_OK)
        goto done;
    memcpy(identity->tenant, cfg.tenant_id, 37);
    memcpy(identity->device, cfg.device_id, 37);
    memcpy(identity->peer, (*connection)->mesh_peer, sizeof identity->peer);
    identity->certificate_expires = expires;
    identity->verified_seconds = mesh_verified_seconds;
    identity->verified_monotonic_us = mesh_verified_monotonic_us;
    identity->revision_first = reserved + 1;
    identity->revision_limit = next + 1;
    (*connection)->device_expires = expires;
    int64_t lifetime = expires - mesh_verified_seconds;
    if (lifetime > 300)
        lifetime = 300;
    (*connection)->mesh_deadline_us = mesh_verified_monotonic_us + lifetime * INT64_C(1000000);
    result = ESP_OK;
done:
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
esp_err_t wendy_pki_mesh_connect(const char* host, unsigned port, const char* peer,
    wendy_pki_connection** connection, struct wendy_pki_mesh_identity* identity)
{
    return mesh_connect(host, port, peer, connection, identity, NULL, false, false);
}
esp_err_t wendy_pki_mesh_stream(const struct wendy_pki_stream* stream, bool server,
    const char* peer, wendy_pki_connection** connection, struct wendy_pki_mesh_identity* identity)
{
    if (!stream || !stream->read || !stream->write || !stream->wait) return ESP_ERR_INVALID_ARG;
    return mesh_connect(NULL, 0, peer, connection, identity, stream, server, false);
}

esp_err_t wendy_pki_mesh_stream_same_tenant(const struct wendy_pki_stream* stream,
    wendy_pki_connection** connection, struct wendy_pki_mesh_identity* identity)
{
    if (!stream || !stream->read || !stream->write || !stream->wait) return ESP_ERR_INVALID_ARG;
    return mesh_connect(NULL, 0, NULL, connection, identity, stream, false, true);
}

#endif

#if CONFIG_WENDY_MESH_CLOUD_UPLINK
/* Reuse this boot's fresh signed time and existing credentials. A borrowed
 * uplink cannot bootstrap enrollment, rotate identity, or accept a new pin. */
static esp_err_t uplink_connect(const char* host, const char* gateway, const char* interface, const char* resolver,
    wendy_pki_connection** connection, int64_t* deadline)
{
    if (!connection || !deadline || (gateway && (!host ||
        !wendy_identity_uuid((const unsigned char*)gateway, strlen(gateway)))))
        return ESP_ERR_INVALID_ARG;
    *connection = NULL;
    *deadline = 0;
    pthread_mutex_lock(&identity_lock);
    WendyConfEnrollment cfg = WendyConfEnrollment_init_zero;
    struct wendy_conf_enrollment_data data = { 0 };
    nvs_handle_t h = 0;
    bool opened = false;
    uint8_t *key = NULL, *cert = NULL;
    size_t key_size = 0, cert_size = 0;
    time_t expires = 0;
    esp_err_t result = ESP_FAIL;
    int64_t now = esp_timer_get_time();
    if (!identity_use_allowed() || !wendy_conf_is_current() || mesh_verified_seconds <= 0
        || now < mesh_verified_monotonic_us
        || now - mesh_verified_monotonic_us >= INT64_C(300000000)
        || wendy_conf_copy_enrollment(&cfg, &data) != ESP_OK
        || validate_config_and_trust(&cfg, &data) || open_identity(&h) != ESP_OK)
        goto done;
    opened = true;
    char principal[106];
    snprintf(principal, sizeof principal, "spiffe://wendy.sh/tenant/%.36s/device/%.36s",
        cfg.tenant_id, cfg.device_id);
    time_t verified_now = mesh_verified_seconds + (now - mesh_verified_monotonic_us) / 1000000;
    if (identity_key(h, &cfg, &key, &key_size) || load_blob(h, "certificate", &cert, &cert_size)
        || wendy_pki_verify_identity(cert, cert_size, data.device_roots.data,
            data.device_roots.size, key, key_size, principal, verified_now, &expires)) goto done;
    int status = gateway
        ? pki_tls_gateway_connect(host, 18867, cfg.tenant_id, cfg.device_id, gateway, key, key_size,
            (const char*)cert, data.device_roots, connection)
        : pki_tls_bound_connect(cfg.broker_host, cfg.broker_port, interface, resolver, key, key_size,
            (const char*)cert, data.https_roots, connection);
    if (status || !wendy_conf_is_current() || wendy_pki_reset_in_progress()) goto done;
    if (gateway && (*connection)->operator_expires < expires)
        expires = (*connection)->operator_expires;
    int64_t lifetime = expires - mesh_verified_seconds;
    if (lifetime > 300) lifetime = 300;
    *deadline = mesh_verified_monotonic_us + lifetime * INT64_C(1000000);
    if (*deadline <= esp_timer_get_time()) goto done;
    (*connection)->relay_expires_us = *deadline;
    result = ESP_OK;
done:
    if (result != ESP_OK && *connection) { wendy_pki_close(*connection); *connection = NULL; }
    if (key) { erase(key, key_size); free(key); }
    free(cert);
    free(data.storage);
    erase(cfg.token, sizeof cfg.token);
    if (opened) nvs_close(h);
    pthread_mutex_unlock(&identity_lock);
    return result;
}
esp_err_t wendy_pki_gateway_connect(const char* host, const char* gateway,
    wendy_pki_connection** connection, int64_t* deadline)
{
    return uplink_connect(host, gateway, NULL, NULL, connection, deadline);
}
bool wendy_pki_probe_direct(const char* interface, const char* resolver)
{
    wendy_pki_connection* connection = NULL;
    int64_t deadline;
    bool ok = uplink_connect(NULL, NULL, interface, resolver, &connection, &deadline) == ESP_OK;
    wendy_pki_close(connection);
    return ok;
}
#endif

static esp_err_t accept_peer(int fd, wendy_pki_connection **connection,
                              const struct wendy_lite_trust *trust, bool allow_device)
{
    pthread_mutex_lock(&identity_lock);
    esp_err_t result = ESP_ERR_INVALID_STATE;
    if (identity_use_allowed()) result = accept_identity_peer(fd, connection, trust, allow_device, NULL);
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
        result = accept_identity_peer(-1, connection, NULL, false, stream);
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
