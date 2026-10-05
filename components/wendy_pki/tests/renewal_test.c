/* Exercise the production connection flow with in-memory NVS and failed HTTP
 * renewal. Cryptographic validation itself is covered by verify_test. */
#include "wendy_pki_internal.h"
#undef ROOT_SIZE
#define ROOT_SIZE(kind) build_roots_size
static size_t build_roots_size = 1;
#include "../src/wendy_pki.c"
#include <assert.h>

const uint8_t wendy_pki_device_roots_start[] = {0};
const uint8_t wendy_pki_tsa_roots_start[] = {0};
const uint8_t wendy_pki_https_roots_start[] = {0};
static struct wendy_conf_enrollment_data usb_data;
static const uint8_t usb_roots[] = {1};
static int bad_roots;
int wendy_pki_verify_roots(const uint8_t *pem, size_t size)
{
    return !pem || !size || bad_roots ? -1 : 0;
}
static const time_t signed_now = 1800000000;
static time_t clock_now, stored_expiry;
static bool have_certificate, invalid_certificate, expire_during_renewal;
static int renewal_calls, broker_calls, identity_checks;
static uint8_t key_der[256];
static size_t key_der_size;
static WendyConfEnrollment config = {
    .tenant_id = "2558fd76-afc7-466e-9613-6b715296a526",
    .device_id = "lite-test",
    .token = "test-token",
    .csr_url = "https://csr.example/v1/2558fd76-afc7-466e-9613-6b715296a526",
    .time_url = "https://time.example",
    .broker_host = "broker.example",
    .broker_port = 5055,
};

time_t time(time_t *out)
{
    if (out)
        *out = clock_now;
    return clock_now;
}
int settimeofday(const struct timeval *tv, const struct timezone *tz)
{
    (void)tz;
    clock_now = tv->tv_sec;
    return 0;
}
int64_t esp_timer_get_time(void) { return 0; }
void esp_fill_random(void *out, size_t size) { memset(out, 1, size); }
esp_err_t nvs_flash_init_partition(const char *p) { return ESP_OK; }
esp_err_t nvs_open_from_partition(const char *p, const char *n, int mode, nvs_handle_t *h)
{
    *h = 1;
    return ESP_OK;
}
void nvs_close(nvs_handle_t h) {}
esp_err_t nvs_get_i64(nvs_handle_t h, const char *name, int64_t *out)
{
    *out = signed_now;
    return ESP_OK;
}
esp_err_t nvs_set_i64(nvs_handle_t h, const char *name, int64_t value) { return ESP_OK; }
esp_err_t nvs_commit(nvs_handle_t h) { return ESP_OK; }
esp_err_t nvs_erase_key(nvs_handle_t h, const char *name) { return ESP_OK; }
esp_err_t nvs_get_blob(nvs_handle_t h, const char *name, void *out, size_t *size)
{
    const void *data;
    size_t n;
    if (!strcmp(name, "key"))
    {
        data = key_der;
        n = key_der_size;
    }
    else if (!strcmp(name, "certificate") && have_certificate)
    {
        data = "stored";
        n = 6;
    }
    else
        return ESP_ERR_NVS_NOT_FOUND;
    if (out)
    {
        assert(*size >= n);
        memcpy(out, data, n);
    }
    *size = n;
    return ESP_OK;
}
esp_err_t nvs_set_blob(nvs_handle_t h, const char *name, const void *data, size_t size)
{
    /* A failed renewal must never replace the stored identity. */
    assert(strcmp(name, "certificate"));
    return ESP_OK;
}
esp_err_t nvs_get_str(nvs_handle_t h, const char *name, char *out, size_t *size)
{
    const char *value = !strcmp(name, "tenant") ? config.tenant_id : config.device_id;
    assert(*size >= strlen(value) + 1);
    strcpy(out, value);
    *size = strlen(value) + 1;
    return ESP_OK;
}
esp_err_t nvs_set_str(nvs_handle_t h, const char *name, const char *value) { return ESP_OK; }
esp_err_t wendy_conf_copy_enrollment(WendyConfEnrollment *out,
                                     struct wendy_conf_enrollment_data *data)
{
    *out = config;
    *data = usb_data;
    return ESP_OK;
}

size_t wendy_pki_time_request(uint8_t out[128], const uint8_t nonce[32]) { return 1; }
int wendy_pki_verify_time(const uint8_t *input, size_t size, const uint8_t nonce[32],
                          const uint8_t *roots, size_t roots_size, time_t floor, time_t *out)
{
    assert(roots == (config.provision_trust ? usb_roots : wendy_pki_tsa_roots_start));
    *out = signed_now;
    return 0;
}
int wendy_pki_verify_identity(const uint8_t *pem, size_t size, const uint8_t *roots,
                              size_t roots_size, const uint8_t *key, size_t key_size,
                              const char *principal, time_t now, time_t *expires)
{
    identity_checks++;
    assert(roots == (config.provision_trust ? usb_roots : wendy_pki_device_roots_start));
    assert(size == 6 && !memcmp(pem, "stored", 6));
    *expires = stored_expiry;
    return invalid_certificate || now >= stored_expiry ? -1 : 0;
}
int pki_http_post(const char *url, const char *type, const char *token, const void *body,
                  size_t body_size, const uint8_t *key, size_t key_size, const char *cert,
                  struct wendy_conf_span roots, uint8_t **response, size_t *response_size)
{
    if (!strcmp(type, "application/timestamp-query"))
    {
        *response = malloc(1);
        *response_size = 1;
        return 0;
    }
    renewal_calls++;
    if (have_certificate)
    {
        assert(cert && !strcmp(cert, "stored") && key && !token);
    }
    else
    {
        assert(!cert && !key && token);
    }
    if (expire_during_renewal)
        clock_now = stored_expiry;
    return -1;
}
int pki_tls_connect(const char *host, unsigned port, const uint8_t *key, size_t key_size,
                    const char *cert, struct wendy_conf_span roots, wendy_pki_connection **out)
{
    broker_calls++;
    assert(roots.data == (config.provision_trust ? usb_roots : wendy_pki_https_roots_start));
    assert(cert && !strcmp(cert, "stored"));
    assert(clock_now < stored_expiry && !invalid_certificate);
    return 0;
}
cJSON *cJSON_CreateObject(void) { return calloc(1, sizeof(cJSON)); }
cJSON *cJSON_AddStringToObject(cJSON *o, const char *k, const char *v) { return o; }
char *cJSON_PrintUnformatted(const cJSON *o) { return strdup("{}"); }
cJSON *cJSON_ParseWithLength(const char *s, size_t n) { return NULL; }
cJSON *cJSON_GetObjectItemCaseSensitive(const cJSON *o, const char *k) { return NULL; }
int cJSON_IsString(const cJSON *o) { return 0; }
void cJSON_Delete(cJSON *o) { free(o); }

static void reset(void)
{
    clock_now = signed_now;
    config.provision_trust = false;
    usb_data = (struct wendy_conf_enrollment_data){0};
    bad_roots = 0;
    build_roots_size = 1;
    stored_expiry = signed_now + 3600;
    have_certificate = true;
    invalid_certificate = expire_during_renewal = false;
    renewal_calls = broker_calls = identity_checks = 0;
}
int main(int argc, char **argv)
{
    assert(argc == 2);
    FILE *f = fopen(argv[1], "rb");
    assert(f);
    key_der_size = fread(key_der, 1, sizeof key_der, f);
    fclose(f);
    assert(key_der_size > 0);
    wendy_pki_connection *connection = NULL;

    reset();
    assert(wendy_pki_connect(&connection) == ESP_OK);
    assert(renewal_calls == 1 && broker_calls == 1 && identity_checks == 2);
    /* The next connection retries renewal instead of disabling it. */
    assert(wendy_pki_connect(&connection) == ESP_OK);
    assert(renewal_calls == 2 && broker_calls == 2 && identity_checks == 4);

    reset();
    expire_during_renewal = true;
    assert(wendy_pki_connect(&connection) != ESP_OK);
    assert(renewal_calls == 1 && broker_calls == 0 && identity_checks == 2);

    reset();
    stored_expiry = signed_now;
    assert(wendy_pki_connect(&connection) != ESP_OK);
    assert(renewal_calls == 0 && broker_calls == 0);

    reset();
    invalid_certificate = true;
    assert(wendy_pki_connect(&connection) != ESP_OK);
    assert(renewal_calls == 0 && broker_calls == 0);

    reset();
    have_certificate = false;
    assert(wendy_pki_connect(&connection) != ESP_OK);
    assert(renewal_calls == 1 && broker_calls == 0 && identity_checks == 0);

    reset();
    stored_expiry = signed_now + 172800;
    assert(wendy_pki_connect(&connection) == ESP_OK);
    assert(renewal_calls == 0 && broker_calls == 1 && identity_checks == 1);
    reset();
    config.provision_trust = true;
    usb_data.device_roots = usb_data.tsa_roots = usb_data.https_roots =
        (struct wendy_conf_span){usb_roots, sizeof usb_roots};
    assert(wendy_pki_connect(&connection) == ESP_OK);
    assert(broker_calls == 1);
    config.provision_trust = false;
    assert(wendy_pki_connect(&connection) != ESP_OK);
    assert(broker_calls == 1);
    config.provision_trust = true;
    usb_data.tsa_roots.size = 0;
    assert(wendy_pki_connect(&connection) != ESP_OK);
    assert(broker_calls == 1);
    usb_data.tsa_roots.size = sizeof usb_roots;
    bad_roots = 1;
    assert(wendy_pki_connect(&connection) != ESP_OK);
    assert(broker_calls == 1);
    reset();
    build_roots_size = 0;
    assert(wendy_pki_connect(&connection) != ESP_OK);
    assert(broker_calls == 0 && renewal_calls == 0);
    wolfSSL_Cleanup();
    puts("renewal fallback tests passed");
}
