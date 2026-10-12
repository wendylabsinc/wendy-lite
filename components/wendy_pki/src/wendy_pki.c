#include "cJSON.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "wendy_conf.h"
#include "wendy_pki_internal.h"
#include <unistd.h>
#include "wendy_pki_verify.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <mbedtls/pk.h>
#include <psa/crypto.h>
#include <mbedtls/sha256.h>
#include <mbedtls/x509_csr.h>

static const char *TAG = "wendy_pki";
static pthread_once_t crypto_once = PTHREAD_ONCE_INIT;
static int crypto_ok;
static void init_crypto(void) { crypto_ok = psa_crypto_init() == PSA_SUCCESS; }
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
    const char *keys[] = {"key", "certificate", "pending", "tenant", "device", "nonce"};
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
static int refresh_time(nvs_handle_t h, const char *url,
                        const struct wendy_conf_enrollment_data *data)
{
    uint8_t nonce[32], request[128], *response = NULL;
    size_t response_size = 0;
    esp_fill_random(nonce, sizeof nonce);
    nonce[0] = (nonce[0] & 0x7f) | 1;
    size_t n = wendy_pki_time_request(request, nonce);
    if (!n)
        return -1;
    int64_t started = esp_timer_get_time();
    if (pki_http_post(url, "application/timestamp-query", NULL, request, n, NULL, 0, NULL,
                      data->https_roots, &response, &response_size))
        return -1;
    int64_t floor = 0;
    time_t when = 0;
    int result = -1;
    if (esp_timer_get_time() - started <= 30000000 && nvs_get_i64(h, "floor", &floor) == ESP_OK &&
        !wendy_pki_verify_time(response, response_size, nonce, data->tsa_roots.data,
                               data->tsa_roots.size, floor, &when))
        result = set_floor(h, when);
    free(response);
    return result;
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
    mbedtls_pk_context k;
    mbedtls_pk_init(&k);
    int result = -1;
    *key = malloc(256);
    if (!*key || mbedtls_pk_setup(&k, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)) ||
        mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(k), wendy_pki_rng, NULL)) goto done;
    int n = mbedtls_pk_write_key_der(&k, *key, 256);
    if (n <= 0) goto done;
    memmove(*key, *key+256-n, n);
    *size = n;
    if (nvs_set_blob(h, "key", *key, *size) != ESP_OK ||
        nvs_set_str(h, "tenant", cfg->tenant_id) != ESP_OK ||
        nvs_set_str(h, "device", cfg->device_id) != ESP_OK || nvs_commit(h) != ESP_OK) goto done;
    result = 0;
done:
    mbedtls_pk_free(&k);
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
    if (mbedtls_pk_parse_key(&k, key, key_size, NULL, 0, wendy_pki_rng, NULL) ||
        mbedtls_x509write_csr_set_subject_name(&csr, subject)) goto fail;
    mbedtls_x509write_csr_set_key(&csr, &k);
    mbedtls_x509write_csr_set_md_alg(&csr, MBEDTLS_MD_SHA256);
    if (mbedtls_x509write_csr_pem(&csr, (unsigned char *)pem, 4096, wendy_pki_rng, NULL)) goto fail;
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
    uint8_t *pending = NULL;
    size_t pending_size = 0;
    const char *certificate = NULL;
    if (!old && !load_blob(h, "pending", &pending, &pending_size))
    {
        certificate = (char *)pending;
        goto verify;
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
    if (pki_http_post(url, "application/json", old ? NULL : cfg->token, json, strlen(json),
                      old ? key : NULL, old ? key_size : 0, old, data->https_roots,
                      &response, &response_size))
        goto done;
    reply = cJSON_ParseWithLength((char *)response, response_size);
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
     * one-use token cannot fetch it again after a verification/storage failure. */
    if (!old && (nvs_set_blob(h, "pending", certificate, strlen(certificate)) != ESP_OK ||
                 nvs_commit(h) != ESP_OK))
        ESP_LOGW(TAG, "could not retain pending issuance response");
verify:
    size_t n = pending ? pending_size : strlen(certificate);
    if (wendy_pki_verify_identity((uint8_t *)certificate, n, data->device_roots.data,
                                  data->device_roots.size, key, key_size, principal, time(NULL),
                                  expires))
        goto done;
    esp_err_t saved = nvs_set_blob(h, "certificate", certificate, n);
    if (saved == ESP_OK)
        saved = nvs_commit(h);
    if (saved != ESP_OK)
    {
        ESP_LOGE(TAG, "saving issued certificate: %s", esp_err_to_name(saved));
        goto done;
    }
    nvs_erase_key(h, "pending");
    nvs_commit(h);
    *issued = strdup(certificate);
    if (!*issued)
        goto done;
    result = 0;
done:
    free(pending);
    free(csr);
    free(json);
    free(response);
    cJSON_Delete(body);
    cJSON_Delete(reply);
    return result;
}
static int valid_config(const WendyConfEnrollment *c)
{
    if (strlen(c->tenant_id) != 36 || !c->device_id[0] || !c->broker_host[0] || !c->broker_port ||
        c->broker_port > 65535)
        return 0;
    for (int i = 0; i < 36; i++)
        if (i == 8 || i == 13 || i == 18 || i == 23)
        {
            if (c->tenant_id[i] != '-')
                return 0;
        }
        else if (!strchr("0123456789abcdef", c->tenant_id[i]))
            return 0;
    if (strspn(c->device_id, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.") !=
        strlen(c->device_id))
        return 0;
    char suffix[48];
    snprintf(suffix, sizeof suffix, "/v1/%s", c->tenant_id);
    size_t n = strlen(c->csr_url), s = strlen(suffix);
    return n > s && !strcmp(c->csr_url + n - s, suffix) && !strncmp(c->csr_url, "https://", 8) &&
           !strncmp(c->time_url, "https://", 8);
}
/* A USB-authorized configuration is the only runtime source of trust.
 * Never substitute a chain returned by an enrollment or timestamp endpoint. */
static int select_trust(const WendyConfEnrollment *cfg, struct wendy_conf_enrollment_data *data)
{
    if (!cfg->provision_trust)
    {
        if (data->device_roots.size || data->tsa_roots.size || data->https_roots.size)
            return -1;
        data->device_roots = (struct wendy_conf_span){wendy_pki_device_roots_start, ROOT_SIZE(device)};
        data->tsa_roots = (struct wendy_conf_span){wendy_pki_tsa_roots_start, ROOT_SIZE(tsa)};
        data->https_roots = (struct wendy_conf_span){wendy_pki_https_roots_start, ROOT_SIZE(https)};
    }
    return wendy_pki_verify_roots(data->device_roots.data, data->device_roots.size) ||
           wendy_pki_verify_roots(data->tsa_roots.data, data->tsa_roots.size) ||
           wendy_pki_verify_roots(data->https_roots.data, data->https_roots.size) ? -1 : 0;
}
static esp_err_t connect_identity(wendy_pki_connection **connection)
{
    pthread_once(&crypto_once, init_crypto);
    if (!crypto_ok)
        return ESP_FAIL;
    WendyConfEnrollment cfg = WendyConfEnrollment_init_zero;
    struct wendy_conf_enrollment_data data;
    esp_err_t copy_result = wendy_conf_copy_enrollment(&cfg, &data);
    if (copy_result != ESP_OK)
    {
        erase(cfg.token, sizeof cfg.token);
        return copy_result;
    }
    if (!valid_config(&cfg) || select_trust(&cfg, &data))
    {
        ESP_LOGE(TAG, "Invalid enrollment configuration or missing/invalid CA bundles; provision device and HTTPS trust roots over USB");
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
    if (stored)
    {
        if (wendy_pki_verify_identity(stored, stored_size, data.device_roots.data,
                                      data.device_roots.size, key, key_size, principal, time(NULL),
                                      &expires))
        {
            ESP_LOGE(TAG, "stored identity invalid or expired; operator recovery required");
            goto done;
        }
    }
    if (!stored || expires - time(NULL) < 86400)
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
    if (pki_tls_connect(cfg.broker_host, cfg.broker_port, key, key_size,
                        fresh ? fresh : (char *)stored, data.https_roots, connection))
        goto done;
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

static esp_err_t accept_identity_operator(int fd, wendy_pki_connection **connection,
    const struct wendy_lite_trust *trust)
{
    pthread_once(&crypto_once, init_crypto);
    WendyConfEnrollment cfg = WendyConfEnrollment_init_zero;
    struct wendy_conf_enrollment_data data = {0};
    nvs_handle_t h = 0;
    bool opened = false;
    uint8_t *key = NULL, *cert = NULL;
    size_t key_size = 0, cert_size = 0;
    time_t expires;
    esp_err_t result = ESP_FAIL;
    if (!crypto_ok || wendy_conf_copy_enrollment(&cfg, &data) != ESP_OK ||
        !valid_config(&cfg) || select_trust(&cfg, &data) || open_identity(&h) != ESP_OK)
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
    int64_t deadline = esp_timer_get_time() + (trust ? 10000000 : 15000000);
    int accepted = pki_tls_accept(fd, key, key_size, (char *)cert,
                                 data.device_roots, cfg.tenant_id, connection, deadline);
    fd = -1; /* pki_tls_accept owns the socket, including failures. */
    if (!accepted) {
        if (!trust || (!mbedtls_sha256((uint8_t *)principal, strlen(principal), (*connection)->device_hash, 0) &&
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
    free(cert);
    free(data.storage);
    erase(cfg.token, sizeof cfg.token);
    if (opened) nvs_close(h);
    return result;
}

static esp_err_t accept_operator(int fd, wendy_pki_connection **connection,
                                  const struct wendy_lite_trust *trust)
{
    pthread_mutex_lock(&identity_lock);
    esp_err_t result = ESP_ERR_INVALID_STATE;
    if (identity_use_allowed()) result = accept_identity_operator(fd, connection, trust);
    else close(fd);
    pthread_mutex_unlock(&identity_lock);
    return result;
}

esp_err_t wendy_pki_accept(int fd, wendy_pki_connection **connection)
{
    return accept_operator(fd, connection, NULL);
}
esp_err_t wendy_pki_accept_relay(int fd, const struct wendy_lite_trust *trust,
                                  wendy_pki_connection **connection)
{
    if (!trust) { close(fd); return ESP_ERR_INVALID_ARG; }
    return accept_operator(fd, connection, trust);
}
