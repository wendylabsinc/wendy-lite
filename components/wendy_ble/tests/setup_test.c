#include "wendy_ble_setup.h"
#include "wendy_ble_setup_wire.h"
#include "wendy_ble_setup.pb.h"
#include "wendy_conf.h"
#include "wendy_pki.h"
#include "wendy_wifi.h"
#include "pb_encode.h"
#include "pb_decode.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static bool configured, installed, resetting, wifi = true, pki_valid = true, persist_ok = true;
static unsigned writes, connections, scans, challenges;
bool wendy_conf_has_enrollment(void) { return configured; }
bool wendy_pki_reset_in_progress(void) { return resetting; }
const char *wendy_conf_get_device_id(void) { return "80456b2d29b4"; }
esp_err_t wendy_pki_challenge(bool status, char nonce[65], bool *enrolled) {
    *enrolled = installed; nonce[0] = 0;
    if (!status) { ++challenges; memset(nonce, '1', 64); nonce[64] = 0; }
    return ESP_OK;
}
esp_err_t wendy_pki_validate_setup(const WendyConfEnrollment *c, const struct wendy_conf_enrollment_data *d) {
    assert(c->token[0] && d->signed_time.size);
    return pki_valid ? ESP_OK : ESP_FAIL;
}
esp_err_t wendy_conf_write(const void *data, size_t size, enum wendy_conf_write_mode mode) {
    assert(data && size && mode == WENDY_CONF_WRITE_MODE_SETUP_ENROLLMENT);
    ++writes;
    if (!persist_ok) return ESP_FAIL;
    configured = true;
    return ESP_OK;
}
bool wendy_wifi_is_connected(void) { return wifi; }
esp_err_t wendy_wifi_try_connect(const char *ssid, const char *password) {
    assert(!strcmp(ssid, "lab") && !strcmp(password, "test-only"));
    ++connections;
    return ESP_OK;
}
esp_err_t wendy_wifi_scan(wifi_ap_record_t *ap, uint16_t *count) {
    assert(*count == 24); ++scans; *count = 1;
    *ap = (wifi_ap_record_t){.ssid = "lab", .rssi = -65, .authmode = WIFI_AUTH_WPA2_PSK};
    return ESP_OK;
}
esp_err_t esp_wifi_sta_get_ap_info(wifi_ap_record_t *ap) {
    *ap = (wifi_ap_record_t){.ssid = "lab"}; return ESP_OK;
}

static uint8_t response[4096];
static size_t response_size;
static bool reboot;
static uint32_t call_bytes(const uint8_t *request, size_t size) {
    assert(wble_setup_dispatch(request, size, response, sizeof response, &response_size, &reboot));
    uint32_t tag; struct wble_setup_span body;
    assert(wble_setup_unwrap(response, response_size, &tag, &body));
    return tag;
}
static uint32_t call(uint32_t command, const uint8_t *body, size_t size) {
    uint8_t request[4096]; size_t written;
    assert(wble_setup_wrap(command, body, size, request, sizeof request, &written));
    return call_bytes(request, written);
}
static bool span_encode(pb_ostream_t *s, const pb_field_t *f, void *const *arg) {
    const char *text = *arg;
    return pb_encode_tag_for_field(s, f) && pb_encode_string(s, (const uint8_t *)text, strlen(text));
}
static size_t enrollment(uint8_t body[4096]) {
    WendyConf conf = WendyConf_init_zero;
    conf.device_name = (pb_callback_t){.funcs.encode = span_encode, .arg = "esp-setup-test"};
    conf.has_enrollment = true;
    strcpy(conf.enrollment.tenant_id, "00000000-0000-4000-8000-000000000001");
    strcpy(conf.enrollment.device_id, "00000000-0000-4000-8000-000000000002");
    strcpy(conf.enrollment.token, "test-only");
    conf.enrollment.signed_time = (pb_callback_t){.funcs.encode = span_encode, .arg = "test-only"};
    uint8_t config[2048];
    pb_ostream_t stream = pb_ostream_from_buffer(config, sizeof config);
    assert(pb_encode(&stream, WendyConf_fields, &conf));
    size_t size;
    assert(wble_setup_wrap(6, config, stream.bytes_written, body, 4096, &size));
    return size;
}
int main(void) {
    assert(call(18, NULL, 0) == 19 && !reboot && challenges == 0);
    const uint8_t nonce[] = {8, 1};
    assert(call(18, nonce, sizeof nonce) == 19 && challenges == 1);
    assert(call(1, NULL, 0) == 1 && scans == 1);
    assert(call(3, NULL, 0) == 3);
    const uint8_t wifi_body[] = {10, 3, 'l', 'a', 'b', 18, 9, 't','e','s','t','-','o','n','l','y'};
    assert(call(2, wifi_body, sizeof wifi_body) == 2 && connections == 1);
    for (uint32_t tag = 4; tag < 40; ++tag) {
        if (tag == 18 || tag == 19) continue;
        assert(call(tag, NULL, 0) == 10 && !reboot);
    }
    // Duplicate/concatenated commands must not execute either mutation.
    const uint8_t duplicate[] = {10, 0, 10, 0};
    assert(call_bytes(duplicate, sizeof duplicate) == 10 && scans == 1);
    const uint8_t truncated[] = {10, 4, 0};
    assert(call_bytes(truncated, sizeof truncated) == 10);
    // Existing configuration, installed certificate, and reset independently close setup.
    for (int state = 0; state < 3; ++state) {
        configured = state == 0; installed = state == 1; resetting = state == 2;
        assert(call(1, NULL, 0) == 10);
        assert(call(2, wifi_body, sizeof wifi_body) == 10);
        assert(call(19, NULL, 0) == 10 && !reboot);
        assert(call(18, nonce, sizeof nonce) == (resetting ? 10u : 19u));
        assert(challenges == 1 && scans == 1 && connections == 1 && writes == 0);
    }
    configured = installed = resetting = false;
    uint8_t body[4096]; size_t size = enrollment(body);
    wifi = false;
    // Offline enrollment still validates the nonce and configuration and must
    // persist successfully. Its acknowledgment remains pending, never issued.
    pki_valid = false;
    assert(call(19, body, size) == 10 && writes == 0 && !reboot);
    pki_valid = true; persist_ok = false;
    assert(call(19, body, size) == 10 && writes == 1 && !reboot);
    persist_ok = true;
    assert(call(19, body, size) == 20 && writes == 2 && reboot);
    uint32_t tag; struct wble_setup_span encoded;
    assert(wble_setup_unwrap(response, response_size, &tag, &encoded));
    wendy_lite_setup_Enrolled accepted = wendy_lite_setup_Enrolled_init_zero;
    pb_istream_t stream = pb_istream_from_buffer(encoded.data, encoded.size);
    assert(pb_decode(&stream, wendy_lite_setup_Enrolled_fields, &accepted));
    assert(accepted.pending && strstr(accepted.principal_uri, "/device/00000000-0000-4000-8000-000000000002"));
    assert(call(19, body, size) == 10 && writes == 2 && !reboot);
    puts("BLE setup dispatch boundaries passed");
}
