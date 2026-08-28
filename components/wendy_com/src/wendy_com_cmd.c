#include <string.h>
#include <inttypes.h>
#include "wendy_com_cmd.h"
#include "wendy_com_msg.pb.h"
#include "esp_log.h"
#include "esp_system.h"
#include "wendy_com_common.h"
#include "wendy_com_stdio_pump.h"
#include "wendy_stdio.h"
#include <pb_encode.h>


static const char *TAG = "wcom_cmd";
static const struct wcom_app_delegate *_app_delegate;

// At most one push (app or conf) may be in progress at a time.
enum _push_kind { PUSH_NONE, PUSH_APP, PUSH_CONF };
static enum _push_kind _push_kind = PUSH_NONE;
static int _pushing_client_id = 0;


WendyComResult wcom_cmd_ping(void)
{
    ESP_LOGI(TAG, "PING");
    return WendyComResult_WENDY_COM_RESULT_OK;
}

WendyComResult wcom_cmd_reboot(bool app_auto_start, uint32_t app_auto_start_delay_ms)
{
    ESP_LOGI(TAG, "REBOOT auto_start=%d delay=%" PRIu32 "ms",
             (int)app_auto_start, app_auto_start_delay_ms);
    if (_app_delegate && _app_delegate->on_reboot)
        return _app_delegate->on_reboot(app_auto_start, app_auto_start_delay_ms);
    return WendyComResult_WENDY_COM_RESULT_OK;
}

WendyComResult wcom_cmd_app_push_begin(int client_id, size_t size, WendyComAppType app_type)
{
    ESP_LOGI(TAG, "APP_PUSH_BEGIN client=%d size=%zu type=%s", client_id, size,
             app_type == WendyComAppType_WENDY_COM_APP_TYPE_NATIVE ? "native" : "wasm");
    if (_push_kind != PUSH_NONE) {
        ESP_LOGW(TAG, "APP_PUSH_BEGIN from client=%d while client=%d is pushing", client_id, _pushing_client_id);
        return WendyComResult_WENDY_COM_RESULT_BUSY;
    }
    _push_kind = PUSH_APP;
    _pushing_client_id = client_id;
    if (_app_delegate && _app_delegate->on_app_push_begin)
        return _app_delegate->on_app_push_begin(size, app_type);
    return WendyComResult_WENDY_COM_RESULT_OK;
}

WendyComResult wcom_cmd_app_push_data(int client_id, size_t offset, const uint8_t *data, size_t size)
{
    ESP_LOGI(TAG, "APP_PUSH_DATA client=%d offset=%zu size=%zu", client_id, offset, size);
    if (_push_kind != PUSH_APP || client_id != _pushing_client_id) {
        ESP_LOGW(TAG, "APP_PUSH_DATA from unexpected client=%d (expected=%d)", client_id, _pushing_client_id);
        return WendyComResult_WENDY_COM_RESULT_BUSY;
    }
    if (_app_delegate && _app_delegate->on_app_push_data)
        return _app_delegate->on_app_push_data(offset, data, size);
    return WendyComResult_WENDY_COM_RESULT_OK;
}

WendyComResult wcom_cmd_app_push_end(int client_id)
{
    ESP_LOGI(TAG, "APP_PUSH_END client=%d", client_id);
    if (_push_kind != PUSH_APP || client_id != _pushing_client_id) {
        ESP_LOGW(TAG, "APP_PUSH_END from unexpected client=%d (expected=%d)", client_id, _pushing_client_id);
        return WendyComResult_WENDY_COM_RESULT_BUSY;
    }
    _push_kind = PUSH_NONE;
    _pushing_client_id = 0;
    if (_app_delegate && _app_delegate->on_app_push_end)
        return _app_delegate->on_app_push_end();
    return WendyComResult_WENDY_COM_RESULT_OK;
}

WendyComResult wcom_cmd_conf_push_begin(int client_id, size_t size, WendyComConfPushMode mode)
{
    ESP_LOGI(TAG, "CONF_PUSH_BEGIN client=%d size=%zu mode=%s", client_id, size,
             mode == WendyComConfPushMode_WENDY_COM_CONF_PUSH_MODE_UPDATE ? "update" : "replace");
    if (_push_kind != PUSH_NONE) {
        ESP_LOGW(TAG, "CONF_PUSH_BEGIN from client=%d while client=%d is pushing", client_id, _pushing_client_id);
        return WendyComResult_WENDY_COM_RESULT_BUSY;
    }
    _push_kind = PUSH_CONF;
    _pushing_client_id = client_id;
    if (_app_delegate && _app_delegate->on_conf_push_begin)
        return _app_delegate->on_conf_push_begin(size, mode);
    return WendyComResult_WENDY_COM_RESULT_OK;
}

WendyComResult wcom_cmd_conf_push_data(int client_id, size_t offset, const uint8_t *data, size_t size)
{
    ESP_LOGI(TAG, "CONF_PUSH_DATA client=%d offset=%zu size=%zu", client_id, offset, size);
    if (_push_kind != PUSH_CONF || client_id != _pushing_client_id) {
        ESP_LOGW(TAG, "CONF_PUSH_DATA from unexpected client=%d (expected=%d)", client_id, _pushing_client_id);
        return WendyComResult_WENDY_COM_RESULT_BUSY;
    }
    if (_app_delegate && _app_delegate->on_conf_push_data)
        return _app_delegate->on_conf_push_data(offset, data, size);
    return WendyComResult_WENDY_COM_RESULT_OK;
}

WendyComResult wcom_cmd_conf_push_end(int client_id)
{
    ESP_LOGI(TAG, "CONF_PUSH_END client=%d", client_id);
    if (_push_kind != PUSH_CONF || client_id != _pushing_client_id) {
        ESP_LOGW(TAG, "CONF_PUSH_END from unexpected client=%d (expected=%d)", client_id, _pushing_client_id);
        return WendyComResult_WENDY_COM_RESULT_BUSY;
    }
    _push_kind = PUSH_NONE;
    _pushing_client_id = 0;
    if (_app_delegate && _app_delegate->on_conf_push_end)
        return _app_delegate->on_conf_push_end();
    return WendyComResult_WENDY_COM_RESULT_OK;
}

WendyComResult wcom_cmd_app_start(int client_id)
{
    ESP_LOGI(TAG, "APP_START client=%d", client_id);
    if (_app_delegate && _app_delegate->on_app_start)
        return _app_delegate->on_app_start();
    return WendyComResult_WENDY_COM_RESULT_OK;
}

WendyComResult wcom_cmd_app_stop(int client_id)
{
    ESP_LOGI(TAG, "APP_STOP client=%d", client_id);
    if (_app_delegate && _app_delegate->on_app_stop)
        return _app_delegate->on_app_stop();
    return WendyComResult_WENDY_COM_RESULT_OK;
}

static bool _encode_string(pb_ostream_t *stream, const pb_field_t *field, void * const *arg)
{
    const char *str = *arg;
    return pb_encode_tag_for_field(stream, field) &&
           pb_encode_string(stream, (const uint8_t *)str, strlen(str));
}

WendyComResult wcom_cmd_get_device_identity(WendyComDeviceIdentity *out)
{
    ESP_LOGI(TAG, "GET_DEVICE_IDENTITY");
    const char *id = "???", *name = "???", *display_name = "???";
    if (_app_delegate && _app_delegate->on_get_device_identity)
        _app_delegate->on_get_device_identity(&id, &name, &display_name);
    out->id.funcs.encode           = _encode_string;
    out->id.arg                    = (void *)id;
    out->name.funcs.encode         = _encode_string;
    out->name.arg                  = (void *)name;
    out->display_name.funcs.encode = _encode_string;
    out->display_name.arg          = (void *)display_name;
    return WendyComResult_WENDY_COM_RESULT_OK;
}

WendyComResult wcom_cmd_get_device_info(WendyComDeviceInfo *out)
{
    ESP_LOGI(TAG, "GET_DEVICE_INFO");
    const char *os = "???", *os_version = "???", *cpu_architecture = "???", *target = "???";
    bool wasm_app_support = false, native_app_support = false;
    if (_app_delegate && _app_delegate->on_get_device_info)
        _app_delegate->on_get_device_info(&os, &os_version, &cpu_architecture, &target,
                                          &wasm_app_support, &native_app_support);
    out->os.funcs.encode               = _encode_string;
    out->os.arg                        = (void *)os;
    out->os_version.funcs.encode       = _encode_string;
    out->os_version.arg                = (void *)os_version;
    out->cpu_architecture.funcs.encode = _encode_string;
    out->cpu_architecture.arg          = (void *)cpu_architecture;
    out->target.funcs.encode           = _encode_string;
    out->target.arg                    = (void *)target;
    /* out->board is left unset: nothing determines the board yet, and an
       omitted field means "board not known" */
    out->wasm_app_support              = wasm_app_support;
    out->native_app_support            = native_app_support;
    return WendyComResult_WENDY_COM_RESULT_OK;
}

WendyComResult wcom_cmd_console_attach(int client_id, uint32_t event_id, uint32_t duration_ms, bool blocking)
{
    ESP_LOGI(TAG, "CONSOLE_ATTACH client=%d event_id=%u duration=%ums blocking=%d",
             client_id, (unsigned)event_id, (unsigned)duration_ms, (int)blocking);
    return wcom_stdio_pump_attach(client_id, event_id, duration_ms, blocking);
}

WendyComResult wcom_cmd_console_detach(int client_id, uint32_t event_id)
{
    ESP_LOGI(TAG, "CONSOLE_DETACH client=%d event_id=%u", client_id, (unsigned)event_id);
    return wcom_stdio_pump_detach(client_id, event_id);
}

// Logs at DEBUG, unlike the other wrappers: this fires per keystroke, and an
// INFO log would itself be captured and streamed back to the attached console.
void wcom_cmd_console_stdin_data(int client_id, const uint8_t *data, size_t size)
{
    ESP_LOGD(TAG, "CONSOLE_STDIN client=%d size=%zu", client_id, size);
    size_t accepted = wendy_stdio_put_stdin_data(data, size);
    if (accepted < size)
        ESP_LOGW(TAG, "CONSOLE_STDIN client=%d dropped %zu of %zu bytes",
                 client_id, size - accepted, size);
}

void wcom_cmd_client_disconnected(int client_id)
{
    if (_push_kind != PUSH_NONE && client_id == _pushing_client_id) {
        ESP_LOGW(TAG, "client %d disconnected while pushing, aborting push", client_id);
        enum _push_kind kind = _push_kind;
        _push_kind = PUSH_NONE;
        _pushing_client_id = 0;
        if (kind == PUSH_APP && _app_delegate && _app_delegate->on_app_push_abort)
            _app_delegate->on_app_push_abort();
        else if (kind == PUSH_CONF && _app_delegate && _app_delegate->on_conf_push_abort)
            _app_delegate->on_conf_push_abort();
    }
    wcom_stdio_pump_client_disconnected(client_id);
}

void wcom_cmd_set_app_delegate(const struct wcom_app_delegate *delegate)
{
    _app_delegate = delegate;
}
