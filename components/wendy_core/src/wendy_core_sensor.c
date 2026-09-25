#include <stdatomic.h>
#include <stdbool.h>
#include <inttypes.h>

#include "esp_log.h"

#include "wendy_com.h"
#include "wendy_com_sensor.h"
#include "wendy_core_sensor.h"

#if CONFIG_WENDY_WIFI_ENABLED
#include "wendy_server.h"
#endif

static const char *TAG = "wendy_core_sensor";

void wendy_core_register_sensor_link_source(const struct wcom_sensor_link_delegate *delegate)
{
    wcom_set_sensor_link_delegate(delegate);
    #if CONFIG_WENDY_WIFI_ENABLED
    struct wendy_server_caps caps = { .sensor_link = true };
    wendy_server_set_caps(caps);
    #endif
}

/* ── Sensor-link streaming, callable from any task ──────────────────── */

/* wcom_sensor_* runs on the com task only, so each of these hands its work
 * over with wcom_exec(). A queued op node belongs to the queue until its
 * func() starts, and re-queuing it before then silently corrupts the com
 * task's intrusive op list — so every op carries a flag, taken on submit and
 * released once func() is done reading the node, and a second submit is
 * refused rather than allowed to overwrite one still in flight. */

static struct {
    struct wcom_operation base;
    int client_id;
    uint32_t channel_id;
} s_stream_begin_op, s_stream_end_op;

static struct {
    struct wcom_operation base;
    int client_id;
    uint32_t channel_id;
    const void *data;
    size_t size;
    uint64_t ts_us;
    void (*done)(uint32_t channel_id);
} s_frame_op;

static atomic_bool s_stream_begin_pending = false;
static atomic_bool s_stream_end_pending   = false;
static atomic_bool s_frame_pending        = false;

static bool take_op(atomic_bool *pending)
{
    bool expected = false;
    return atomic_compare_exchange_strong(pending, &expected, true);
}

static void stream_begin_exec(struct wcom_operation *op)
{
    wcom_sensor_stream_begin(s_stream_begin_op.client_id, s_stream_begin_op.channel_id);
    atomic_store(&s_stream_begin_pending, false);
}

static void stream_end_exec(struct wcom_operation *op)
{
    wcom_sensor_stream_end(s_stream_end_op.client_id, s_stream_end_op.channel_id);
    atomic_store(&s_stream_end_pending, false);
}

static void frame_exec(struct wcom_operation *op)
{
    WendyComResult result = wcom_sensor_stream_push(
        s_frame_op.client_id, s_frame_op.channel_id, s_frame_op.data,
        s_frame_op.size, s_frame_op.ts_us, s_frame_op.done);
    /* On OK the frame owns the buffer until its own done callback runs;
       otherwise nobody else will hand it back, so do it here. */
    void (*done)(uint32_t channel_id) = s_frame_op.done;
    uint32_t channel_id = s_frame_op.channel_id;
    atomic_store(&s_frame_pending, false);
    if (result != WendyComResult_WENDY_COM_RESULT_OK && done)
        done(channel_id);
}

void wendy_core_sensor_stream_begin(int client_id, uint32_t channel_id)
{
    if (!take_op(&s_stream_begin_pending)) {
        ESP_LOGW(TAG, "sensor stream begin already pending");
        return;
    }
    s_stream_begin_op.base.func = stream_begin_exec;
    s_stream_begin_op.client_id = client_id;
    s_stream_begin_op.channel_id = channel_id;
    wcom_exec(&s_stream_begin_op.base);
}

void wendy_core_sensor_stream_push(int client_id, uint32_t channel_id, const void *data, size_t size, uint64_t ts_us, void (* done)(uint32_t channel_id))
{
    if (!take_op(&s_frame_pending)) {
        /* The previous frame has not reached the com task yet. Drop this one,
           but hand the buffer straight back: the caller is waiting on done. */
        ESP_LOGW(TAG, "frame dropped on channel %" PRIu32 ": previous one still pending", channel_id);
        if (done)
            done(channel_id);
        return;
    }
    s_frame_op.base.func = frame_exec;
    s_frame_op.client_id = client_id;
    s_frame_op.channel_id = channel_id;
    s_frame_op.data = data;
    s_frame_op.size = size;
    s_frame_op.ts_us = ts_us;
    s_frame_op.done = done;
    wcom_exec(&s_frame_op.base);
}

void wendy_core_sensor_stream_end(int client_id, uint32_t channel_id)
{
    if (!take_op(&s_stream_end_pending)) {
        ESP_LOGW(TAG, "sensor stream end already pending");
        return;
    }
    s_stream_end_op.base.func = stream_end_exec;
    s_stream_end_op.client_id = client_id;
    s_stream_end_op.channel_id = channel_id;
    wcom_exec(&s_stream_end_op.base);
}
