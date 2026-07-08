#include <string.h>
#include "wendy_com_cmd.h"
#include "wendy_com_msg.pb.h"
#include "esp_log.h"
#include "esp_system.h"
#include "wendy_com_common.h"
#include <pb_encode.h>


static const char *TAG = "wcom_cmd";
static const struct wcom_app_delegate *_app_delegate;
static int _pushing_client_id = 0;


WendyComResult wcom_cmd_protocol_version(const WendyComProtocolVersionParams *in, WendyComProtocolVersion *out)
{
    ESP_LOGI(TAG, "GET_PROTOCOL_VERSION (client %u.%u)", in->major, in->minor);
    out->major = 1;
    out->minor = 0;
    if (in->major != 1) {
        return WendyComResult_WENDY_COM_RESULT_BAD_PROTOCOL_VERSION;
    }
    return WendyComResult_WENDY_COM_RESULT_OK;
}

WendyComResult wcom_cmd_ping(void)
{
    ESP_LOGI(TAG, "PING");
    return WendyComResult_WENDY_COM_RESULT_OK;
}

WendyComResult wcom_cmd_reboot(void)
{
    ESP_LOGI(TAG, "REBOOT");
    if (_app_delegate && _app_delegate->on_reboot)
        return _app_delegate->on_reboot();
    return WendyComResult_WENDY_COM_RESULT_OK;
}

WendyComResult wcom_cmd_app_push_begin(int client_id, size_t size, WendyComAppType app_type)
{
    ESP_LOGI(TAG, "APP_PUSH_BEGIN client=%d size=%zu type=%s", client_id, size,
             app_type == WendyComAppType_WENDY_COM_APP_TYPE_NATIVE ? "native" : "wasm");
    if (_pushing_client_id != 0) {
        ESP_LOGW(TAG, "APP_PUSH_BEGIN from client=%d while client=%d is pushing", client_id, _pushing_client_id);
        return WendyComResult_WENDY_COM_RESULT_BUSY;
    }
    _pushing_client_id = client_id;
    if (_app_delegate && _app_delegate->on_app_push_begin)
        return _app_delegate->on_app_push_begin(size, app_type);
    return WendyComResult_WENDY_COM_RESULT_OK;
}

WendyComResult wcom_cmd_app_push_data(int client_id, size_t offset, const uint8_t *data, size_t size)
{
    ESP_LOGI(TAG, "APP_PUSH_DATA client=%d offset=%zu size=%zu", client_id, offset, size);
    if (client_id != _pushing_client_id) {
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
    if (client_id != _pushing_client_id) {
        ESP_LOGW(TAG, "APP_PUSH_END from unexpected client=%d (expected=%d)", client_id, _pushing_client_id);
        return WendyComResult_WENDY_COM_RESULT_BUSY;
    }
    _pushing_client_id = 0;
    if (_app_delegate && _app_delegate->on_app_push_end)
        return _app_delegate->on_app_push_end();
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

void wcom_cmd_client_disconnected(int client_id)
{
    if (client_id == _pushing_client_id) {
        ESP_LOGW(TAG, "client %d disconnected while pushing, aborting push", client_id);
        _pushing_client_id = 0;
        if (_app_delegate && _app_delegate->on_app_push_abort)
            _app_delegate->on_app_push_abort();
    }
}

void wcom_cmd_set_app_delegate(const struct wcom_app_delegate *delegate)
{
    _app_delegate = delegate;
}
