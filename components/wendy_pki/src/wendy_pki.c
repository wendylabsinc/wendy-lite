#include "cJSON.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "wendy_conf.h"
#include "wendy_pki_internal.h"
#include "wendy_pki_verify.h"
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
static int seed_clock(nvs_handle_t h, struct wendy_conf_span seed)
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
            !wendy_pki_verify_time(seed.data, seed.size, nonce, wendy_pki_tsa_roots_start,
                                   ROOT_SIZE(tsa), floor, &when))
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
static int refresh_time(nvs_handle_t h, const char *url)
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
                      &response, &response_size))
        return -1;
    int64_t floor = 0;
    time_t when = 0;
    int result = -1;
    if (esp_timer_get_time() - started <= 30000000 && nvs_get_i64(h, "floor", &floor) == ESP_OK &&
        !wendy_pki_verify_time(response, response_size, nonce, wendy_pki_tsa_roots_start,
                               ROOT_SIZE(tsa), floor, &when))
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
static int issue(nvs_handle_t h, const WendyConfEnrollment *cfg, const uint8_t *key,
                 size_t key_size, const char *old, const char *principal, char **issued,
                 time_t *expires)
{
    char *csr = make_csr(key, key_size, cfg->device_id), *json = NULL;
    uint8_t *response = NULL;
    size_t response_size = 0;
    int result = -1;
    cJSON *body = NULL, *reply = NULL;
    char url[280];
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
                      old ? key : NULL, old ? key_size : 0, old, &response, &response_size))
        goto done;
    reply = cJSON_ParseWithLength((char *)response, response_size);
    if (!reply)
        goto done;
    cJSON *cert = cJSON_GetObjectItemCaseSensitive(reply, "certificate");
    if (!cJSON_IsString(cert) || !cert->valuestring)
        goto done;
    size_t n = strlen(cert->valuestring);
    if (wendy_pki_verify_identity((uint8_t *)cert->valuestring, n, wendy_pki_device_roots_start,
                                  ROOT_SIZE(device), key, key_size, principal, time(NULL), expires))
        goto done;
    if (nvs_set_blob(h, "certificate", cert->valuestring, n) != ESP_OK || nvs_commit(h) != ESP_OK)
        goto done;
    *issued = strdup(cert->valuestring);
    if (!*issued)
        goto done;
    result = 0;
done:
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
esp_err_t wendy_pki_connect(wendy_pki_connection **connection)
{
    pthread_once(&crypto_once, init_crypto);
    if (!crypto_ok)
        return ESP_FAIL;
    WendyConfEnrollment cfg;
    uint8_t *seed = NULL;
    size_t seed_size = 0;
    esp_err_t copy_result = wendy_conf_copy_enrollment(&cfg, &seed, &seed_size);
    if (copy_result != ESP_OK)
        return copy_result;
    if (!valid_config(&cfg))
    {
        free(seed);
        erase(cfg.token, sizeof cfg.token);
        return ESP_ERR_INVALID_ARG;
    }
    nvs_handle_t h;
    if (open_identity(&h) != ESP_OK)
    {
        free(seed);
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
    if (seed_clock(h, (struct wendy_conf_span){.data = seed, .size = seed_size}) ||
        refresh_time(h, cfg.time_url))
    {
        ESP_LOGE(TAG, "verified current PKI time unavailable; cloud connection held");
        goto done;
    }
    free(seed);
    seed = NULL;
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
        if (wendy_pki_verify_identity(stored, stored_size, wendy_pki_device_roots_start,
                                      ROOT_SIZE(device), key, key_size, principal, time(NULL),
                                      &expires))
        {
            ESP_LOGE(TAG, "stored identity invalid or expired; operator recovery required");
            goto done;
        }
    }
    if (!stored || expires - time(NULL) < 86400)
    {
        if (issue(h, &cfg, key, key_size, (char *)stored, principal, &fresh, &expires))
        {
            /* Renewal can fail transiently. Recheck the stored identity after
             * the request, since it may have expired while the request ran. */
            if (!stored ||
                wendy_pki_verify_identity(stored, stored_size, wendy_pki_device_roots_start,
                                          ROOT_SIZE(device), key, key_size, principal,
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
                        fresh ? fresh : (char *)stored, connection))
        goto done;
    result = ESP_OK;
done:
    if (key)
    {
        erase(key, key_size);
        free(key);
    }
    erase(cfg.token, sizeof cfg.token);
    free(seed);
    free(stored);
    free(fresh);
    nvs_close(h);
    return result;
}
