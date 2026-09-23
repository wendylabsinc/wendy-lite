#ifndef WENDY_COM_COMMON_H
#define WENDY_COM_COMMON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "wendy_com_msg.pb.h"
#include "sensorlink.pb.h"

struct wcom_app_delegate {
    WendyComResult (*on_app_push_begin)(size_t size, WendyComAppType app_type);
    WendyComResult (*on_app_push_data)(size_t offset, const uint8_t *data, size_t size);
    WendyComResult (*on_app_push_end)(void);
    void (*on_app_push_abort)(void);
    WendyComResult (*on_conf_push_begin)(size_t size, WendyComConfPushMode mode);
    WendyComResult (*on_conf_push_data)(size_t offset, const uint8_t *data, size_t size);
    WendyComResult (*on_conf_push_end)(void);
    void (*on_conf_push_abort)(void);
    WendyComResult (*on_app_start)(void);
    WendyComResult (*on_app_stop)(void);
    WendyComResult (*on_reboot)(bool app_auto_start, uint32_t app_auto_start_delay_ms);
    void (*on_get_device_identity)(const char **id, const char **name, const char **display_name);
    void (*on_get_device_info)(const char **os, const char **os_version,
                               const char **cpu_architecture, const char **target,
                               bool *wasm_app_support, bool *native_app_support);
};

// A single sensor/camera/microphone channel, as reported to the delegate.
// Mirrors wendy.lite.sensorlink.SensorDescriptor without exposing pb_callback_t
// or the oneof union machinery: strings are plain `const char *`, kept alive
// by the caller for at least the duration of the wcom_cmd_sensor_link_get_manifest()
// call (same lifetime contract as on_get_device_identity/on_get_device_info).
enum wcom_sensor_format_kind {
    WCOM_SENSOR_FORMAT_NONE = 0,
    WCOM_SENSOR_FORMAT_VIDEO,
    WCOM_SENSOR_FORMAT_AUDIO,
    WCOM_SENSOR_FORMAT_SENSOR,
};

struct wcom_sensor_descriptor {
    uint32_t channel_id;
    wendy_lite_sensorlink_SensorDescriptor_Kind kind;
    const char *name;
    enum wcom_sensor_format_kind format_kind;
    union {
        struct {
            wendy_lite_sensorlink_VideoFormat_Codec codec;
            uint32_t width, height, fps;
        } video;
        struct {
            wendy_lite_sensorlink_AudioFormat_Codec codec;
            uint32_t sample_rate, channels;
        } audio;
        struct {
            const char *schema;
            uint32_t rate_hz, sample_bytes;
        } sensor;
    } format;
};

// Must match the max_count values in components/wendy_com/proto/sensorlink.options
// (nanopb .options can't reference a C macro, so keep these in sync by hand).
#define WCOM_SENSOR_LINK_MAX_SENSORS  16
#define WCOM_SENSOR_LINK_MAX_CHANNELS 16

// What a sensor source reports back. Deliberately not WendyComResult: that is
// the protocol's wire enum, and wendy_com_cmd translates into it.
enum wcom_sensor_link_result {
    WCOM_SENSOR_LINK_OK = 0,
    WCOM_SENSOR_LINK_FAIL,
};

struct wcom_sensor_link_delegate {
    // Fill up to max_sensors entries of `sensors`; set *sensor_count to how
    // many were written (0 if none / not ready yet). The manifest's asset id
    // is not asked for here — it comes from wendy_conf.
    enum wcom_sensor_link_result (*on_sensor_link_get_manifest)(struct wcom_sensor_descriptor *sensors,
                                                   size_t max_sensors,
                                                   size_t *sensor_count);
    // client_id identifies the requesting link/channel (same id space as
    // wcom_cmd_console_attach's client_id), so the delegate knows who to
    // eventually stream SensorFrames to / stop streaming to. channel_ids/count
    // come straight from the decoded (bounded) request.
    enum wcom_sensor_link_result (*on_sensor_link_subscribe)(int client_id, const uint32_t *channel_ids, size_t count);
    enum wcom_sensor_link_result (*on_sensor_link_unsubscribe)(int client_id, const uint32_t *channel_ids, size_t count);
    // Called when client_id goes away — its channel closed, or its whole link
    // dropped. Any frame still in flight for it has already had its done
    // callback run, the link clearing its tx queue before it reports the
    // disconnect, so the producer's buffer is back in its hands by now. The
    // stream is closed too: this is a cue to stop capturing, not to send
    // anything more.
    void (*on_sensor_link_disconnected)(int client_id);
};

// An operation to run on the com task. Set `func`; `next` belongs to the queue
// and is never read from the caller. Once queued, the node is the queue's until
// its `func` starts running: until then, do not modify any part of it, nor any
// payload embedded around it. See wcom_core_exec() in wendy_com_link.h.
struct wcom_operation {
    void(* func)(struct wcom_operation *op);
    struct wcom_operation *next;
};

#endif
