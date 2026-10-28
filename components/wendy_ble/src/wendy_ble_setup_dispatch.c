#include "wendy_ble_setup.h"
#include "wendy_ble_setup_wire.h"
#include "wendy_ble_setup.pb.h"
#include "wendy_conf.h"
#include "wendy_pki.h"
#include "wendy_wifi.h"
#include "pb_decode.h"
#include "mbedtls/platform_util.h"
#include <stdio.h>
#include <string.h>

static bool error_reply(const char *text, uint8_t *out, size_t capacity, size_t *written)
{
    wendy_lite_setup_Error error = wendy_lite_setup_Error_init_zero;
    snprintf(error.message, sizeof error.message, "%s", text);
    return wble_setup_encode(10, wendy_lite_setup_Error_fields, &error, out, capacity, written);
}

static bool decode(struct wble_setup_span span, const pb_msgdesc_t *fields, void *message)
{
    pb_istream_t input = pb_istream_from_buffer(span.data, span.size);
    return pb_decode(&input, fields, message);
}

static bool capture(pb_istream_t *stream, const pb_field_t *field, void **arg)
{
    (void)field;
    struct wendy_conf_span *span = *arg;
    if (span->data) return false; // Reject duplicate data, including empty fields.
    *span = (struct wendy_conf_span){stream->state, stream->bytes_left};
    return pb_read(stream, NULL, stream->bytes_left);
}

static bool valid_name(struct wendy_conf_span name)
{
    if (!name.size || name.size > 63) return false;
    const uint8_t *p = name.data;
    if (p[0] < 'a' || p[0] > 'z' || p[name.size - 1] == '-') return false;
    for (size_t i = 0; i < name.size; ++i)
        if (!(p[i] >= 'a' && p[i] <= 'z') && !(p[i] >= '0' && p[i] <= '9') && p[i] != '-')
            return false;
    return true;
}

static bool enroll(struct wble_setup_span body, uint8_t *out, size_t capacity,
                   size_t *written, bool *reboot)
{
    struct wble_setup_span config;
    uint32_t tag;
    // Only field 6 is accepted; class-B fields and duplicate configs fail closed.
    if (!wble_setup_unwrap(body.data, body.size, &tag, &config) || tag != 6 ||
        !config.size || config.size > WBLE_SETUP_MAX_CONFIG)
        return error_reply("Invalid Lite enrollment configuration", out, capacity, written);
    WendyConf conf = WendyConf_init_zero;
    struct wendy_conf_span name = {0};
    struct wendy_conf_enrollment_data data = {0};
    conf.device_name = (pb_callback_t){.funcs.decode = capture, .arg = &name};
    conf.enrollment.signed_time = (pb_callback_t){.funcs.decode = capture, .arg = &data.signed_time};
    conf.enrollment.device_roots = (pb_callback_t){.funcs.decode = capture, .arg = &data.device_roots};
    conf.enrollment.tsa_roots = (pb_callback_t){.funcs.decode = capture, .arg = &data.tsa_roots};
    conf.enrollment.https_roots = (pb_callback_t){.funcs.decode = capture, .arg = &data.https_roots};
    pb_istream_t input = pb_istream_from_buffer(config.data, config.size);
    bool valid = pb_decode_noinit(&input, WendyConf_fields, &conf) && conf.has_enrollment &&
                 valid_name(name);
    size_t total = data.signed_time.size;
    const struct wendy_conf_span roots[] = {data.device_roots, data.tsa_roots, data.https_roots};
    for (size_t i = 0; i < 3; ++i) {
        valid = valid && roots[i].size <= WENDY_CONF_MAX_TRUST_BUNDLE;
        total += roots[i].size;
    }
    valid = valid && total <= WENDY_CONF_MAX_ENROLLMENT_DATA &&
        wendy_pki_validate_setup(&conf.enrollment, &data) == ESP_OK;
    wendy_lite_setup_Enrolled response = wendy_lite_setup_Enrolled_init_zero;
    if (valid) {
        snprintf(response.principal_uri, sizeof response.principal_uri,
                 "spiffe://wendy.sh/tenant/%s/device/%s", conf.enrollment.tenant_id, conf.enrollment.device_id);
        response.pending = true;
        // Encode before persisting so a caller's short output buffer cannot
        // cause enrollment to happen without an encodable acknowledgment.
        valid = wble_setup_encode(20, wendy_lite_setup_Enrolled_fields, &response, out, capacity, written);
        if (valid) valid = wendy_conf_write(config.data, config.size,
                                           WENDY_CONF_WRITE_MODE_SETUP_ENROLLMENT) == ESP_OK;
    }
    mbedtls_platform_zeroize(&conf, sizeof conf);
    if (!valid) return error_reply("Enrollment rejected; check nonce and configuration", out, capacity, written);
    *reboot = true;
    return true;
}

static int security(wifi_auth_mode_t auth)
{
    switch (auth) {
    case WIFI_AUTH_OPEN: return 1;
    case WIFI_AUTH_WEP: return 2;
    case WIFI_AUTH_WPA_PSK: return 3;
    case WIFI_AUTH_WPA2_PSK: case WIFI_AUTH_WPA_WPA2_PSK: return 4;
    case WIFI_AUTH_WPA3_PSK: case WIFI_AUTH_WPA2_WPA3_PSK: return 5;
    case WIFI_AUTH_WPA2_ENTERPRISE: return 6;
    default: return 0;
    }
}

bool wble_setup_dispatch(const uint8_t *input, size_t size, uint8_t *out, size_t capacity,
                         size_t *written, bool *reboot)
{
    *written = 0;
    *reboot = false;
    uint32_t tag;
    struct wble_setup_span body;
    if (!wble_setup_unwrap(input, size, &tag, &body))
        return error_reply("Invalid setup command", out, capacity, written);
    // Check both persisted configuration and installed identity. A missing
    // configuration must never reopen setup on a board that still has keys.
    bool enrolled = true;
    char nonce[65];
    if (wendy_pki_reset_in_progress() ||
        wendy_pki_challenge(true, nonce, &enrolled) != ESP_OK)
        return error_reply("Setup unavailable", out, capacity, written);
    enrolled |= wendy_conf_has_enrollment();
    if (tag == 18) {
        wendy_lite_setup_StatusCommand command = wendy_lite_setup_StatusCommand_init_zero;
        wendy_lite_setup_Status response = wendy_lite_setup_Status_init_zero;
        if (!decode(body, wendy_lite_setup_StatusCommand_fields, &command))
            return error_reply("Invalid status command", out, capacity, written);
        response.enrolled = enrolled;
        response.lite_supported = !enrolled;
        response.max_config_size = WBLE_SETUP_MAX_CONFIG;
        strcpy(response.device_class, "C");
        snprintf(response.hardware_id, sizeof response.hardware_id, "%s", wendy_conf_get_device_id());
        if (command.request_nonce && !enrolled &&
            wendy_pki_challenge(false, response.nonce, &enrolled) != ESP_OK)
            return error_reply("Cannot create enrollment challenge", out, capacity, written);
        return wble_setup_encode(19, wendy_lite_setup_Status_fields, &response, out, capacity, written);
    }
    if (enrolled) return error_reply("Device already enrolled; setup is closed", out, capacity, written);
    switch (tag) {
    case 1: {
        if (body.size) break;
        wifi_ap_record_t records[24];
        uint16_t count = 24;
        if (wendy_wifi_scan(records, &count) != ESP_OK)
            return error_reply("Wi-Fi scan failed; try again", out, capacity, written);
        wendy_lite_setup_WifiList response = wendy_lite_setup_WifiList_init_zero;
        wifi_ap_record_t connected = {0};
        bool has_ap = wendy_wifi_is_connected() && esp_wifi_sta_get_ap_info(&connected) == ESP_OK;
        response.networks_count = count;
        for (uint16_t i = 0; i < count; ++i) {
            wendy_lite_setup_WifiNetwork *n = &response.networks[i];
            memcpy(n->ssid, records[i].ssid, 32);
            n->ssid[32] = 0;
            n->rssi_dbm = records[i].rssi;
            int strength = 2 * (records[i].rssi + 100);
            n->signal_strength = strength < 0 ? 0 : strength > 100 ? 100 : strength;
            n->security = security(records[i].authmode);
            n->is_connected = has_ap && !memcmp(connected.bssid, records[i].bssid, 6);
        }
        return wble_setup_encode(1, wendy_lite_setup_WifiList_fields, &response, out, capacity, written);
    }
    case 2: {
        wendy_lite_setup_WifiConnect command = wendy_lite_setup_WifiConnect_init_zero;
        wendy_lite_setup_WifiConnected response = wendy_lite_setup_WifiConnected_init_zero;
        bool valid = decode(body, wendy_lite_setup_WifiConnect_fields, &command) && command.ssid[0];
        if (valid) response.success = wendy_wifi_try_connect(command.ssid, command.password) == ESP_OK;
        mbedtls_platform_zeroize(&command, sizeof command);
        if (!response.success) strcpy(response.error_message, "Wi-Fi connection failed; check the network and password");
        return wble_setup_encode(2, wendy_lite_setup_WifiConnected_fields, &response, out, capacity, written);
    }
    case 3: {
        if (body.size) break;
        wendy_lite_setup_WifiStatus response = wendy_lite_setup_WifiStatus_init_zero;
        wifi_ap_record_t ap = {0};
        response.connected = wendy_wifi_is_connected() && esp_wifi_sta_get_ap_info(&ap) == ESP_OK;
        if (response.connected) memcpy(response.ssid, ap.ssid, 32);
        return wble_setup_encode(3, wendy_lite_setup_WifiStatus_fields, &response, out, capacity, written);
    }
    case 19:
        return enroll(body, out, capacity, written, reboot);
    default: break;
    }
    return error_reply("Command unavailable during setup", out, capacity, written);
}
