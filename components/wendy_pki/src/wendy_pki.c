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
#include "wendy_roughtime.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/random.h>

static const char *TAG = "wendy_pki";
static pthread_once_t crypto_once = PTHREAD_ONCE_INIT;
static int crypto_ok;
static void init_crypto(void) { crypto_ok = wolfSSL_Init() == WOLFSSL_SUCCESS; }
int wendy_pki_random(unsigned char *out, unsigned int size)
{
    esp_fill_random(out, size);
    return 0;
}
static pthread_once_t identity_once = PTHREAD_ONCE_INIT;
static esp_err_t identity_ready = ESP_FAIL;
static pthread_mutex_t clock_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint8_t relay_nonce[32];
static int64_t relay_started;
static bool relay_active;
static unsigned relay_mask;
static struct wendy_rt_interval relay_evidence[WENDY_RT_SERVERS];
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
esp_err_t wendy_pki_challenge(bool status_only, char nonce_hex[65], bool *enrolled)
{
    nvs_handle_t h;
    if (open_identity(&h) != ESP_OK)
        return ESP_FAIL;
    size_t size = 0;
    *enrolled = nvs_get_blob(h, "certificate", NULL, &size) == ESP_OK && size > 0;
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
    pthread_mutex_lock(&clock_mutex);
    memcpy(relay_nonce, nonce, 32);
    relay_started = esp_timer_get_time();
    relay_active = r == ESP_OK;
    relay_mask = 0;
    pthread_mutex_unlock(&clock_mutex);
    if (r != ESP_OK)
        return r;
    for (int i = 0; i < 32; i++)
        snprintf(nonce_hex + i * 2, 3, "%02x", nonce[i]);
    return ESP_OK;
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
/* Call with clock_mutex held. Persist only a verified lower bound. */
static int apply_roughtime(struct wendy_rt_interval interval, int64_t *seconds)
{
    nvs_handle_t h;
    if (open_identity(&h) != ESP_OK) return -1;
    int64_t floor = 0;
    esp_err_t err = nvs_get_i64(h, "floor", &floor);
    int result = -1;
    if ((err != ESP_OK && err != ESP_ERR_NVS_NOT_FOUND) || floor < 0 ||
        floor > INT64_MAX / 1000000 || interval.upper < floor * 1000000) goto done;
    if (interval.lower < floor * 1000000) interval.lower = floor * 1000000;
    int64_t next_floor = interval.lower / 1000000;
    if (nvs_set_i64(h, "floor", next_floor) != ESP_OK || nvs_commit(h) != ESP_OK) goto done;
    *seconds = (interval.lower + (interval.upper - interval.lower) / 2) / 1000000;
    struct timeval tv = {.tv_sec = *seconds};
    result = settimeofday(&tv, NULL);
done:
    nvs_close(h);
    return result;
}
esp_err_t wendy_pki_sync_time(unsigned server, const uint8_t *reply, size_t size,
                              bool *synchronized, int64_t *seconds)
{
    *synchronized = false; *seconds = 0;
    if (server >= WENDY_RT_SERVERS) return ESP_ERR_INVALID_ARG;
    pthread_once(&crypto_once, init_crypto);
    if (!crypto_ok) return ESP_FAIL;
    pthread_mutex_lock(&clock_mutex);
    int64_t now = esp_timer_get_time();
    esp_err_t result = ESP_FAIL;
    if (!relay_active || now - relay_started > 30000000 || (relay_mask & (1u << server))) goto done;
    struct wendy_rt_interval interval;
    if (wendy_rt_verify(reply, size, relay_nonce, wendy_rt_servers[server].key, &interval)) goto done;
    interval.lower -= now; interval.upper -= relay_started;
    relay_evidence[server] = interval;
    relay_mask |= 1u << server;
    result = ESP_OK;
    if (!wendy_rt_consensus(relay_evidence, relay_mask, &interval)) {
        now = esp_timer_get_time(); interval.lower += now; interval.upper += now;
        if (apply_roughtime(interval, seconds)) { result = ESP_FAIL; goto done; }
        *synchronized = true;
        relay_active = false; /* Single use: replay cannot advance the clock. */
    }
done:
    pthread_mutex_unlock(&clock_mutex);
    return result;
}
static int refresh_roughtime(void)
{
    struct wendy_rt_interval interval;
    if (wendy_rt_query(&interval)) return -1;
    pthread_mutex_lock(&clock_mutex);
    int64_t seconds;
    int result = apply_roughtime(interval, &seconds);
    pthread_mutex_unlock(&clock_mutex);
    return result;
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
    WC_RNG rng;
    ecc_key k;
    int result = -1;
    if (wc_InitRng(&rng))
        return -1;
    if (wc_ecc_init(&k))
    {
        wc_FreeRng(&rng);
        return -1;
    }
    *key = malloc(256);
    if (!*key)
        goto done;
    if (wc_ecc_make_key_ex(&rng, 32, &k, ECC_SECP256R1))
        goto done;
    int n = wc_EccKeyToDer(&k, *key, 256);
    if (n <= 0)
        goto done;
    *size = n;
    if (nvs_set_blob(h, "key", *key, *size) != ESP_OK ||
        nvs_set_str(h, "tenant", cfg->tenant_id) != ESP_OK ||
        nvs_set_str(h, "device", cfg->device_id) != ESP_OK || nvs_commit(h) != ESP_OK)
        goto done;
    result = 0;
done:
    wc_ecc_free(&k);
    wc_FreeRng(&rng);
    if (result && *key)
    {
        erase(*key, 256);
        free(*key);
        *key = NULL;
    }
    return result;
}
static char *make_csr(const uint8_t *key, size_t key_size, const char *device)
{
    WC_RNG rng;
    ecc_key k;
    Cert *request = NULL;
    uint8_t *der = NULL;
    char *pem = NULL;
    word32 index = 0;
    if (wc_InitRng(&rng))
        return NULL;
    if (wc_ecc_init(&k))
    {
        wc_FreeRng(&rng);
        return NULL;
    }
    if (wc_EccPrivateKeyDecode(key, &index, &k, key_size) || index != key_size)
        goto done;
    request = malloc(sizeof *request);
    der = malloc(4096);
    pem = calloc(1, 4096);
    if (!request || !der || !pem)
        goto fail;
    wc_InitCert(request);
    request->sigType = CTC_SHA256wECDSA;
    if (strlen(device) >= sizeof request->subject.commonName)
        goto fail;
    memcpy(request->subject.commonName, device, strlen(device) + 1);
    int n = wc_MakeCertReq(request, der, 4096, NULL, &k);
    if (n <= 0 || (n = wc_SignCert(n, request->sigType, der, 4096, NULL, &k, &rng)) <= 0 ||
        wc_DerToPem(der, n, (uint8_t *)pem, 4095, CERTREQ_TYPE) <= 0)
        goto fail;
    goto done;
fail:
    free(pem);
    pem = NULL;
done:
    free(request);
    free(der);
    wc_ecc_free(&k);
    wc_FreeRng(&rng);
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
           (!strcmp(c->time_url, "roughtime") || !strncmp(c->time_url, "https://", 8));
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
           (strcmp(cfg->time_url, "roughtime") && wendy_pki_verify_roots(data->tsa_roots.data, data->tsa_roots.size)) ||
           wendy_pki_verify_roots(data->https_roots.data, data->https_roots.size) ? -1 : 0;
}
esp_err_t wendy_pki_connect(wendy_pki_connection **connection)
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
    if (!strcmp(cfg.time_url, "roughtime") ? refresh_roughtime() :
        (seed_clock(h, data.signed_time, data.tsa_roots) || refresh_time(h, cfg.time_url, &data)))
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


esp_err_t wendy_pki_accept(int fd, wendy_pki_connection **connection)
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
    int accepted = pki_tls_accept(fd, key, key_size, (char *)cert,
                                 data.device_roots, cfg.tenant_id, connection);
    fd = -1; /* pki_tls_accept owns the socket, including failures. */
    if (!accepted) result = ESP_OK;
done:
    if (fd >= 0) close(fd);
    if (key) { erase(key, key_size); free(key); }
    free(cert);
    free(data.storage);
    erase(cfg.token, sizeof cfg.token);
    if (opened) nvs_close(h);
    return result;
}
