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
static bool pending_certificate, issuance_success;
static char lite_authority[64], pending_authority[64];
static size_t pending_authority_size;
static bool distinct_issued_certificate, stored_is_issued, pending_is_issued;
static bool issuance_received, fail_post_issue_time;
static time_t issued_not_before, issued_expiry;
static int timestamp_calls;
static const char *response_authority;
static const char *fail_set;
static int authority_writes, lite_accepts, operator_accepts, lan_accepts;
static bool have_key, have_binding, have_nonce, config_cleared, fail_clear;
static int64_t reset_pending;
static uint8_t stored_nonce[32], random_counter;
static const char *fail_erase;
static int commit_calls, fail_commit;
static int clear_calls, erase_calls;
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
void esp_fill_random(void *out, size_t size) { memset(out, ++random_counter, size); }
esp_err_t nvs_flash_init_partition(const char *p) { return ESP_OK; }
esp_err_t nvs_open_from_partition(const char *p, const char *n, int mode, nvs_handle_t *h)
{
    *h = 1;
    return ESP_OK;
}
void nvs_close(nvs_handle_t h) {}
esp_err_t nvs_get_i64(nvs_handle_t h, const char *name, int64_t *out)
{
    if (!strcmp(name, "reset_pending")) {
        if (!reset_pending) return ESP_ERR_NVS_NOT_FOUND;
        *out = reset_pending;
    } else {
        assert(!strcmp(name, "floor"));
        *out = signed_now;
    }
    return ESP_OK;
}
esp_err_t nvs_set_i64(nvs_handle_t h, const char *name, int64_t value)
{
    if (!strcmp(name, "reset_pending")) reset_pending = value;
    else assert(!strcmp(name, "floor"));
    return ESP_OK;
}
esp_err_t nvs_commit(nvs_handle_t h)
{
    return ++commit_calls == fail_commit ? ESP_FAIL : ESP_OK;
}
esp_err_t nvs_erase_key(nvs_handle_t h, const char *name)
{
    if (identity_resetting) {
        assert(config_cleared);
        erase_calls++;
    }
    if (fail_erase && !strcmp(name, fail_erase)) return ESP_FAIL;
    if (!strcmp(name, "pending")) pending_certificate = false;
    else if (!strcmp(name, "lite_ca")) lite_authority[0] = 0;
    else if (!strcmp(name, "pending_ca")) { pending_authority[0] = 0; pending_authority_size = 0; }
    else if (!strcmp(name, "certificate")) have_certificate = false;
    else if (!strcmp(name, "key")) have_key = false;
    else if (!strcmp(name, "tenant") || !strcmp(name, "device")) have_binding = false;
    else if (!strcmp(name, "nonce")) have_nonce = false;
    else if (!strcmp(name, "reset_pending")) reset_pending = 0;
    else assert(0 && "unexpected erased key, signed clock floor must survive");
    return ESP_OK;
}
esp_err_t nvs_get_blob(nvs_handle_t h, const char *name, void *out, size_t *size)
{
    const void *data;
    size_t n;
    if (!strcmp(name, "nonce") && have_nonce) { data = stored_nonce; n = sizeof stored_nonce; }
    else if (!strcmp(name, "key") && have_key)
    {
        data = key_der;
        n = key_der_size;
    }
    else if ((!strcmp(name, "certificate") && have_certificate) ||
             (!strcmp(name, "pending") && pending_certificate))
    {
        data = (!strcmp(name, "certificate") ? stored_is_issued : pending_is_issued) ? "issued" : "stored";
        n = 6;
    }
    else if (!strcmp(name, "lite_ca") && lite_authority[0])
    {
        data = lite_authority;
        n = strlen(lite_authority);
    }
    else if (!strcmp(name, "pending_ca") && pending_authority_size)
    {
        data = pending_authority;
        n = pending_authority_size;
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
    if (fail_set && !strcmp(name, fail_set)) return ESP_FAIL;
    if (!strcmp(name, "nonce")) {
        assert(size == sizeof stored_nonce);
        memcpy(stored_nonce, data, size);
        have_nonce = true;
    }
    if (!strcmp(name, "key")) have_key = true;
    if (!strcmp(name, "pending")) {
        pending_certificate = true;
        pending_is_issued = size == 6 && !memcmp(data, "issued", 6);
    }
    if (!strcmp(name, "lite_ca") || !strcmp(name, "pending_ca"))
    {
        char *out = !strcmp(name, "lite_ca") ? lite_authority : pending_authority;
        assert(size < sizeof lite_authority);
        memcpy(out, data, size);
        out[size] = 0;
        if (out == lite_authority) authority_writes++;
        else pending_authority_size = size;
    }
    if (!strcmp(name, "certificate"))
    {
        assert(issuance_success && !invalid_certificate);
        have_certificate = true;
        stored_is_issued = size == 6 && !memcmp(data, "issued", 6);
    }
    return ESP_OK;
}
esp_err_t nvs_get_str(nvs_handle_t h, const char *name, char *out, size_t *size)
{
    if (!have_binding) return ESP_ERR_NVS_NOT_FOUND;
    const char *value = !strcmp(name, "tenant") ? config.tenant_id : config.device_id;
    assert(*size >= strlen(value) + 1);
    strcpy(out, value);
    *size = strlen(value) + 1;
    return ESP_OK;
}
esp_err_t nvs_set_str(nvs_handle_t h, const char *name, const char *value) { have_binding = true; return ESP_OK; }
esp_err_t wendy_conf_copy_enrollment(WendyConfEnrollment *out,
                                     struct wendy_conf_enrollment_data *data)
{
    if (config_cleared) return ESP_ERR_INVALID_STATE;
    *out = config;
    *data = usb_data;
    return ESP_OK;
}

const char *wendy_conf_get_device_id(void) { return "441bf6804824"; }
esp_err_t wendy_conf_clear_enrollment(void)
{
    clear_calls++;
    assert(reset_pending && identity_resetting);
    assert(pthread_mutex_trylock(&identity_lock) != 0);
    if (fail_clear) return ESP_FAIL;
    config_cleared = true;
    return ESP_OK;
}

size_t wendy_pki_time_request(uint8_t out[128], const uint8_t nonce[32]) { return 1; }
int wendy_pki_verify_time(const uint8_t *input, size_t size, const uint8_t nonce[32],
                          const uint8_t *roots, size_t roots_size, time_t floor, time_t *out)
{
    assert(roots == (config.provision_trust ? usb_roots : wendy_pki_tsa_roots_start));
    *out = issuance_received && distinct_issued_certificate ? issued_not_before : signed_now;
    return 0;
}
int wendy_pki_verify_identity(const uint8_t *pem, size_t size, const uint8_t *roots,
                              size_t roots_size, const uint8_t *key, size_t key_size,
                              const char *principal, time_t now, time_t *expires)
{
    identity_checks++;
    assert(roots == (config.provision_trust ? usb_roots : wendy_pki_device_roots_start));
    assert(size == 6);
    if (!memcmp(pem, "issued", 6)) {
        *expires = issued_expiry;
        return invalid_certificate || now < issued_not_before || now >= issued_expiry ? -1 : 0;
    }
    assert(!memcmp(pem, "stored", 6));
    *expires = stored_expiry;
    return invalid_certificate || now >= stored_expiry ? -1 : 0;
}
int pki_http_post(const char *url, const char *type, const char *token, const void *body,
                  size_t body_size, const uint8_t *key, size_t key_size, const char *cert,
                  struct wendy_conf_span roots, uint8_t **response, size_t *response_size)
{
    if (!strcmp(type, "application/timestamp-query"))
    {
        timestamp_calls++;
        if (issuance_received && fail_post_issue_time) return -1;
        *response = malloc(1);
        *response_size = 1;
        return 0;
    }
    renewal_calls++;
    if (have_certificate)
    {
        assert(cert && (!strcmp(cert, "stored") || !strcmp(cert, "issued")) && key && !token);
    }
    else
    {
        assert(!cert && !key && token);
    }
    if (issuance_success)
    {
        issuance_received = true;
        *response = (uint8_t *)strdup("issued");
        *response_size = 6;
        return 0;
    }
    if (expire_during_renewal)
        clock_now = stored_expiry;
    return -1;
}
int pki_http_post_enrollment(const char *url, const char *type, const char *token,
                  const void *body, size_t body_size, const uint8_t *key, size_t key_size,
                  const char *cert, struct wendy_conf_span roots, uint8_t **response,
                  size_t *response_size, char **lite_authority_header)
{
    *lite_authority_header = NULL;
    int result = pki_http_post(url, type, token, body, body_size, key, key_size, cert,
                               roots, response, response_size);
    if (!result && response_authority)
        *lite_authority_header = strdup(response_authority);
    return result;
}
int wendy_pki_lite_authority_from_header(const char *header, char **pem)
{
    *pem = NULL;
    if (strcmp(header, "valid-new-authority")) return -1;
    *pem = strdup("new-authority-pem");
    return *pem ? 0 : -1;
}
int pki_tls_connect(const char *host, unsigned port, const uint8_t *key, size_t key_size,
                    const char *cert, struct wendy_conf_span roots, wendy_pki_connection **out)
{
    broker_calls++;
    assert(roots.data == (config.provision_trust ? usb_roots : wendy_pki_https_roots_start));
    assert(cert && (!strcmp(cert, "stored") || !strcmp(cert, "issued")));
    assert(clock_now < (!strcmp(cert, "issued") ? issued_expiry : stored_expiry) && !invalid_certificate);
    return 0;
}
cJSON *cJSON_CreateObject(void) { return calloc(1, sizeof(cJSON)); }
cJSON *cJSON_AddStringToObject(cJSON *o, const char *k, const char *v) { return o; }
char *cJSON_PrintUnformatted(const cJSON *o) { return strdup("{}"); }
cJSON *cJSON_ParseWithLength(const char *s, size_t n)
{
    cJSON *o = calloc(1, sizeof *o);
    o->valuestring = distinct_issued_certificate ? "issued" : "stored";
    return o;
}
cJSON *cJSON_GetObjectItemCaseSensitive(const cJSON *o, const char *k) { return (cJSON *)o; }
int cJSON_IsString(const cJSON *o) { return o && o->valuestring; }
void cJSON_Delete(cJSON *o) { free(o); }

static void reset(void)
{
    pending_certificate = issuance_success = false;
    strcpy(lite_authority, "old-authority-pem");
    pending_authority[0] = 0;
    pending_authority_size = 0;
    distinct_issued_certificate = stored_is_issued = pending_is_issued = false;
    issuance_received = fail_post_issue_time = false;
    issued_not_before = signed_now + 10;
    issued_expiry = signed_now + 172800;
    timestamp_calls = 0;
    response_authority = "valid-new-authority";
    fail_set = NULL;
    authority_writes = lite_accepts = operator_accepts = lan_accepts = 0;
    have_key = have_binding = true;
    have_nonce = config_cleared = fail_clear = identity_resetting = false;
    reset_pending = 0;
    fail_erase = NULL;
    commit_calls = fail_commit = clear_calls = erase_calls = 0;
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

static void test_enrollment_reset(void)
{
    char nonce[65], stale[65];
    bool enrolled;
    wendy_pki_connection *connection = NULL;
    reset();
    pending_certificate = true;
    strcpy(pending_authority, "valid-new-authority");
    pending_authority_size = strlen(pending_authority);
    assert(wendy_pki_challenge(false, nonce, &enrolled) == ESP_OK && enrolled);
    /* Background issuance may own the lock during a slow network operation. */
    pthread_mutex_lock(&identity_lock);
    assert(wendy_pki_challenge(true, stale, &enrolled) == ESP_OK && enrolled);
    pthread_mutex_unlock(&identity_lock);
    strcpy(stale, nonce);
    assert(wendy_pki_challenge(false, nonce, &enrolled) == ESP_OK);
    assert(wendy_pki_reset("other-board", nonce) != ESP_OK);
    assert(wendy_pki_reset("441bf6804824", stale) != ESP_OK);
    assert(wendy_pki_reset("441bf6804824", "invalid") != ESP_OK);
    memset(stale, 'z', 64); stale[64] = 0;
    assert(wendy_pki_reset("441bf6804824", stale) != ESP_OK);
    assert(clear_calls == 0 && erase_calls == 0 && have_key && have_certificate);

    fail_clear = true;
    assert(wendy_pki_reset("441bf6804824", nonce) != ESP_OK);
    assert(reset_pending && have_key && have_certificate && erase_calls == 0);
    /* Simulate reboot: the durable marker must still block old issuance. */
    identity_resetting = false;
    assert(wendy_pki_connect(&connection) != ESP_OK);
    assert(broker_calls == 0 && renewal_calls == 0);
    assert(wendy_pki_challenge(true, stale, &enrolled) == ESP_OK && enrolled);
    fail_clear = false;
    fail_erase = "certificate";
    assert(wendy_pki_reset("441bf6804824", nonce) != ESP_OK);
    assert(config_cleared && !have_key && have_certificate && reset_pending);
    fail_erase = NULL;
    fail_commit = commit_calls + 2; /* Fail after the key deletion phase. */
    assert(wendy_pki_reset("441bf6804824", nonce) != ESP_OK);
    assert(!have_certificate && reset_pending);
    assert(wendy_pki_challenge(true, stale, &enrolled) == ESP_OK && enrolled);
    fail_commit = 0;
    assert(wendy_pki_challenge(false, nonce, &enrolled) == ESP_OK && enrolled);
    assert(wendy_pki_reset("441bf6804824", nonce) == ESP_OK);
    assert(!have_key && !have_binding && !have_certificate && !have_nonce && !reset_pending);
    assert(!lite_authority[0] && !pending_authority[0]);
    assert(wendy_pki_challenge(true, stale, &enrolled) == ESP_OK && !enrolled);
    assert(wendy_pki_connect(&connection) != ESP_OK);
    assert(broker_calls == 0 && renewal_calls == 0);
    int64_t floor;
    assert(nvs_get_i64(1, "floor", &floor) == ESP_OK && floor == signed_now);
    /* A lost success reply can be retried with a new challenge. */
    assert(wendy_pki_challenge(false, nonce, &enrolled) == ESP_OK && !enrolled);
    assert(wendy_pki_reset("441bf6804824", nonce) == ESP_OK);

    reset();
    assert(wendy_pki_challenge(false, nonce, &enrolled) == ESP_OK);
    fail_commit = commit_calls + 1;
    assert(wendy_pki_reset("441bf6804824", nonce) != ESP_OK);
    assert(clear_calls == 0 && erase_calls == 0 && have_key && have_certificate);
}

static void test_lite_authority_lifecycle(void)
{
    wendy_pki_connection *connection = NULL;
    reset();
    have_certificate = false;
    lite_authority[0] = 0;
    issuance_success = true;
    response_authority = NULL;
    assert(wendy_pki_connect(&connection) != ESP_OK);
    assert(!have_certificate && !lite_authority[0] && pending_certificate);
    assert(authority_writes == 0 && identity_checks == 0 && broker_calls == 0);
    assert(wendy_pki_connect(&connection) != ESP_OK && renewal_calls == 1);

    reset();
    have_certificate = false;
    lite_authority[0] = 0;
    issuance_success = true;
    response_authority = "invalid-authority";
    assert(wendy_pki_connect(&connection) != ESP_OK);
    assert(!have_certificate && !lite_authority[0] && authority_writes == 0);
    assert(pending_certificate && !strcmp(pending_authority, "invalid-authority"));
    assert(wendy_pki_connect(&connection) != ESP_OK && renewal_calls == 1);

    reset();
    have_certificate = false;
    lite_authority[0] = 0;
    issuance_success = true;
    assert(wendy_pki_connect(&connection) == ESP_OK);
    assert(have_certificate && !strcmp(lite_authority, "new-authority-pem"));
    assert(!pending_certificate && !pending_authority[0] && authority_writes == 1);

    /* The authority and certificate remain paired if activation cannot save
     * the certificate after consuming the one-use enrollment token. */
    reset();
    have_certificate = false;
    lite_authority[0] = 0;
    issuance_success = true;
    fail_set = "certificate";
    assert(wendy_pki_connect(&connection) != ESP_OK);
    assert(pending_certificate && !strcmp(pending_authority, "valid-new-authority"));
    assert(!have_certificate && renewal_calls == 1);
    fail_set = NULL;
    assert(wendy_pki_connect(&connection) == ESP_OK);
    assert(have_certificate && !pending_certificate && !pending_authority[0]);
    assert(!strcmp(lite_authority, "new-authority-pem") && renewal_calls == 1);

    /* Incomplete legacy pending enrollment cannot invent operator trust or
     * spend the consumed token again. */
    reset();
    have_certificate = false;
    lite_authority[0] = 0;
    pending_certificate = true;
    assert(wendy_pki_connect(&connection) != ESP_OK);
    assert(!have_certificate && !lite_authority[0] && renewal_calls == 0);
    strcpy(pending_authority, "invalid-authority");
    pending_authority_size = strlen(pending_authority);
    assert(wendy_pki_connect(&connection) != ESP_OK);
    assert(!have_certificate && !lite_authority[0] && renewal_calls == 0);
    pending_certificate = false;
    assert(wendy_pki_connect(&connection) != ESP_OK);
    assert(!have_certificate && !lite_authority[0] && renewal_calls == 0);

    reset();
    have_certificate = false;
    lite_authority[0] = 0;
    issuance_success = true;
    fail_set = "lite_ca";
    assert(wendy_pki_connect(&connection) != ESP_OK);
    assert(pending_certificate && pending_authority[0] && !have_certificate);
    assert(!lite_authority[0] && renewal_calls == 1);
    fail_set = NULL;
    assert(wendy_pki_connect(&connection) == ESP_OK);
    assert(!strcmp(lite_authority, "new-authority-pem") && renewal_calls == 1);

    reset();
    issuance_success = true;
    assert(wendy_pki_connect(&connection) == ESP_OK);
    assert(!strcmp(lite_authority, "new-authority-pem") && authority_writes == 1);

    reset();
    issuance_success = true;
    response_authority = NULL;
    assert(wendy_pki_connect(&connection) == ESP_OK);
    assert(!strcmp(lite_authority, "old-authority-pem") && authority_writes == 0);

    reset();
    issuance_success = true;
    response_authority = "invalid-authority";
    assert(wendy_pki_connect(&connection) == ESP_OK); /* Valid stored fallback. */
    assert(!strcmp(lite_authority, "old-authority-pem") && authority_writes == 0);
    assert(identity_checks == 2 && broker_calls == 1);

    /* A newly supplied authority cannot overwrite the pin if the accompanying
     * device identity does not verify. */
    reset();
    issuance_success = invalid_certificate = true;
    struct wendy_conf_enrollment_data data = {
        .device_roots = {wendy_pki_device_roots_start, 1},
        .https_roots = {wendy_pki_https_roots_start, 1},
        .tsa_roots = {wendy_pki_tsa_roots_start, 1},
    };
    char *fresh = NULL;
    time_t expires;
    assert(issue(1, &config, &data, key_der, key_der_size, "stored", "principal",
                 &fresh, &expires) != 0);
    assert(!fresh && !strcmp(lite_authority, "old-authority-pem") && authority_writes == 0);

    /* Migration renews a valid long-lived device identity immediately. If the
     * service omits the header, control still works and the next connect retries. */
    reset();
    lite_authority[0] = 0;
    stored_expiry = signed_now + 172800;
    issuance_success = true;
    response_authority = NULL;
    assert(wendy_pki_connect(&connection) == ESP_OK);
    assert(renewal_calls == 1 && !lite_authority[0]);
    response_authority = "valid-new-authority";
    assert(wendy_pki_connect(&connection) == ESP_OK);
    assert(renewal_calls == 2 && !strcmp(lite_authority, "new-authority-pem"));
    assert(wendy_pki_connect(&connection) == ESP_OK);
    assert(renewal_calls == 2);

    reset();
    struct wendy_lite_trust trust = {0};
    assert(wendy_pki_accept_relay(-1, &trust, &connection) != ESP_OK);
    assert(lite_accepts == 1 && operator_accepts == 0 && lan_accepts == 0);
    lite_authority[0] = 0;
    assert(wendy_pki_accept_relay(-1, &trust, &connection) != ESP_OK);
    assert(lite_accepts == 1); /* No fallback to device roots. */
    assert(wendy_pki_accept(-1, &connection) != ESP_OK);
    assert(wendy_pki_accept_lan(-1, &connection) != ESP_OK);
    assert(operator_accepts == 1 && lan_accepts == 1);
}

static void test_post_issuance_time_and_recovery(void)
{
    wendy_pki_connection *connection = NULL;
    reset();
    distinct_issued_certificate = issuance_success = true;
    /* The timestamp obtained before issuance is behind the new notBefore.
     * Validation would fail until the post-response signed-time request. */
    assert(clock_now < issued_not_before);
    time_t expires;
    assert(wendy_pki_verify_identity((uint8_t *)"issued", 6, wendy_pki_device_roots_start,
        1, key_der, key_der_size, "principal", clock_now, &expires) != 0);
    assert(wendy_pki_connect(&connection) == ESP_OK);
    assert(timestamp_calls == 2 && clock_now == issued_not_before);
    assert(stored_is_issued && !pending_certificate && renewal_calls == 1);

    reset();
    distinct_issued_certificate = issuance_success = fail_post_issue_time = true;
    assert(wendy_pki_connect(&connection) == ESP_OK); /* Stored identity fallback. */
    assert(pending_certificate && pending_is_issued && !stored_is_issued);
    assert(!strcmp(lite_authority, "old-authority-pem") && authority_writes == 0);
    assert(timestamp_calls == 2 && renewal_calls == 1 && broker_calls == 1);
    /* The response remains usable even after its predecessor expires. It is
     * verified locally, without a second request using the consumed identity. */
    stored_expiry = signed_now - 1;
    fail_post_issue_time = false;
    assert(wendy_pki_connect(&connection) == ESP_OK);
    assert(stored_is_issued && !pending_certificate && !pending_authority_size);
    assert(renewal_calls == 1 && broker_calls == 2 && timestamp_calls == 4);
    assert(!strcmp(lite_authority, "new-authority-pem"));

    reset();
    distinct_issued_certificate = issuance_success = fail_post_issue_time = true;
    response_authority = NULL;
    assert(wendy_pki_connect(&connection) == ESP_OK);
    assert(pending_certificate && pending_authority_size == 1 && !pending_authority[0]);
    assert(!stored_is_issued && authority_writes == 0);
    fail_post_issue_time = false;
    stored_expiry = signed_now + 259200; /* Replay even without near expiry. */
    assert(wendy_pki_connect(&connection) == ESP_OK);
    assert(stored_is_issued && !pending_certificate && !pending_authority_size);
    assert(renewal_calls == 1 && !strcmp(lite_authority, "old-authority-pem"));

    reset();
    have_certificate = false;
    pending_certificate = true;
    pending_authority[0] = 0;
    pending_authority_size = 1;
    lite_authority[0] = 0;
    assert(wendy_pki_connect(&connection) != ESP_OK); /* Marker cannot authorize initial enrollment. */
    assert(renewal_calls == 0 && !have_certificate && !lite_authority[0]);

    reset();
    issuance_success = true;
    response_authority = "invalid-authority";
    assert(wendy_pki_connect(&connection) == ESP_OK);
    assert(wendy_pki_connect(&connection) == ESP_OK);
    assert(renewal_calls == 1 && pending_certificate && authority_writes == 0);
    assert(!strcmp(lite_authority, "old-authority-pem"));

    for (int fail_authority = 0; fail_authority < 2; fail_authority++) {
        reset();
        issuance_success = true;
        fail_set = fail_authority ? "pending_ca" : "pending";
        assert(wendy_pki_connect(&connection) == ESP_OK); /* Stored fallback. */
        assert(pending_certificate || pending_authority_size);
        assert(pending_certificate == (bool)fail_authority);
        assert((pending_authority_size != 0) == !fail_authority);
        assert(authority_writes == 0 && renewal_calls == 1);
        fail_set = NULL;
        assert(wendy_pki_connect(&connection) == ESP_OK);
        assert(renewal_calls == 1); /* Incomplete retained pair prevents resubmission. */
    }
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
    /* A failed verification retains only a pending response. The retry must
     * verify again and must not spend the one-use enrollment token twice. */
    reset();
    have_certificate = false;
    lite_authority[0] = 0;
    issuance_success = invalid_certificate = true;
    stored_expiry = signed_now + 172800;
    assert(wendy_pki_connect(&connection) != ESP_OK);
    assert(pending_certificate && !have_certificate && broker_calls == 0);
    assert(!strcmp(pending_authority, "valid-new-authority") && !lite_authority[0]);
    assert(renewal_calls == 1 && identity_checks == 1);
    invalid_certificate = false;
    assert(wendy_pki_connect(&connection) == ESP_OK);
    assert(!pending_certificate && have_certificate && broker_calls == 1);
    assert(!pending_authority[0] && !strcmp(lite_authority, "new-authority-pem"));
    assert(renewal_calls == 1 && identity_checks == 2);
    test_lite_authority_lifecycle();
    test_post_issuance_time_and_recovery();
    test_enrollment_reset();
    puts("renewal fallback, Lite authority lifecycle and local enrollment reset tests passed");
}

int pki_tls_accept(int fd, const uint8_t *key, size_t key_size, const char *cert, struct wendy_conf_span roots, const char *tenant, wendy_pki_connection **out, int64_t deadline)
{
    operator_accepts++;
    assert(roots.data == wendy_pki_device_roots_start);
    return -1;
}
int pki_tls_accept_lan(int fd, const uint8_t *key, size_t key_size, const char *cert, struct wendy_conf_span roots, const char *tenant, wendy_pki_connection **out, int64_t deadline)
{
    lan_accepts++;
    assert(roots.data == wendy_pki_device_roots_start);
    return -1;
}
int pki_tls_accept_lite(int fd, const uint8_t *key, size_t key_size, const char *cert, struct wendy_conf_span roots, const char *tenant, wendy_pki_connection **out, int64_t deadline)
{
    lite_accepts++;
    assert(lite_authority[0] && roots.size == strlen(lite_authority));
    assert(!memcmp(roots.data, lite_authority, roots.size));
    return -1;
}

int pki_relay_grant(wendy_pki_connection *c, const struct wendy_lite_trust *t, int64_t d) { (void)c; (void)t; (void)d; return -1; }

void wendy_pki_close(wendy_pki_connection *c) { (void)c; }
