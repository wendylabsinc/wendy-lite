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

/* Each queued operation owns its node until the com task copies its fields.
 * Separate bounded pools keep frame traffic from consuming begin/end capacity.
 * Pool claims use atomics so producers on different cores can submit safely. */
struct sensor_control_op {
    struct wcom_operation base;
    atomic_bool pending;
    int client_id;
    uint32_t channel_id;
    void (*done)(uint32_t channel_id);
};

struct sensor_push_op {
    struct wcom_operation base;
    atomic_bool pending;
    int client_id;
    uint32_t channel_id;
    const void *data;
    size_t size;
    uint64_t ts_us;
    void (*done)(uint32_t channel_id);
};

static struct sensor_control_op s_begin_ops[WCOM_SENSOR_MAX_STREAMS];
static struct sensor_control_op s_end_ops[WCOM_SENSOR_MAX_STREAMS];
static struct sensor_push_op s_push_ops[WCOM_SENSOR_MAX_STREAMS];

static bool take_op(atomic_bool *pending)
{
    bool expected = false;
    return atomic_compare_exchange_strong(pending, &expected, true);
}

static struct sensor_control_op *take_control_op(struct sensor_control_op *ops)
{
    for (size_t i = 0; i < WCOM_SENSOR_MAX_STREAMS; i++) {
        if (take_op(&ops[i].pending))
            return &ops[i];
    }
    return NULL;
}

static void stream_begin_exec(struct wcom_operation *base)
{
    struct sensor_control_op *op = (struct sensor_control_op *)base;
    int client_id = op->client_id;
    uint32_t channel_id = op->channel_id;
    atomic_store(&op->pending, false);
    WendyComResult result = wcom_sensor_stream_begin(client_id, channel_id);
    if (result != WendyComResult_WENDY_COM_RESULT_OK)
        ESP_LOGW(TAG, "sensor stream begin refused on channel %" PRIu32 ": %d", channel_id, result);
}

static void stream_end_exec(struct wcom_operation *base)
{
    struct sensor_control_op *op = (struct sensor_control_op *)base;
    int client_id = op->client_id;
    uint32_t channel_id = op->channel_id;
    void (*done)(uint32_t channel_id) = op->done;
    atomic_store(&op->pending, false);
    wcom_sensor_stream_end(client_id, channel_id);
    if (done)
        done(channel_id);
}

static void stream_push_exec(struct wcom_operation *base)
{
    struct sensor_push_op *op = (struct sensor_push_op *)base;
    int client_id = op->client_id;
    uint32_t channel_id = op->channel_id;
    const void *data = op->data;
    size_t size = op->size;
    uint64_t ts_us = op->ts_us;
    void (*done)(uint32_t channel_id) = op->done;
    atomic_store(&op->pending, false);
    WendyComResult result = wcom_sensor_stream_push(client_id, channel_id, data, size, ts_us, done);
    // Accepted frames own the callback. Refused frames never reached the
    // transport, so their buffers return to the producer here.
    if (result != WendyComResult_WENDY_COM_RESULT_OK && done)
        done(channel_id);
}

void wendy_core_sensor_stream_begin(int client_id, uint32_t channel_id)
{
    struct sensor_control_op *op = take_control_op(s_begin_ops);
    if (!op) {
        ESP_LOGW(TAG, "sensor stream begin queue full");
        return;
    }
    op->base.func = stream_begin_exec;
    op->client_id = client_id;
    op->channel_id = channel_id;
    wcom_exec(&op->base);
}

WendyComResult wendy_core_sensor_stream_try_push(int client_id, uint32_t channel_id,
                                                const void *data, size_t size, uint64_t ts_us,
                                                void (*done)(uint32_t channel_id))
{
    if (!data || size == 0)
        return WendyComResult_WENDY_COM_RESULT_BAD_STATE;
    for (size_t i = 0; i < WCOM_SENSOR_MAX_STREAMS; i++) {
        struct sensor_push_op *op = &s_push_ops[i];
        if (!take_op(&op->pending))
            continue;
        op->base.func = stream_push_exec;
        op->client_id = client_id;
        op->channel_id = channel_id;
        op->data = data;
        op->size = size;
        op->ts_us = ts_us;
        op->done = done;
        wcom_exec(&op->base);
        return WendyComResult_WENDY_COM_RESULT_OK;
    }
    return WendyComResult_WENDY_COM_RESULT_BUSY;
}

void wendy_core_sensor_stream_push(int client_id, uint32_t channel_id, const void *data,
                                   size_t size, uint64_t ts_us, void (*done)(uint32_t channel_id))
{
    WendyComResult result = wendy_core_sensor_stream_try_push(client_id, channel_id,
                                                             data, size, ts_us, done);
    if (result != WendyComResult_WENDY_COM_RESULT_OK && done)
        done(channel_id);
}

void wendy_core_sensor_stream_end(int client_id, uint32_t channel_id, void (*done)(uint32_t channel_id))
{
    struct sensor_control_op *op = take_control_op(s_end_ops);
    if (!op) {
        ESP_LOGW(TAG, "sensor stream end queue full");
        if (done)
            done(channel_id);
        return;
    }
    op->base.func = stream_end_exec;
    op->client_id = client_id;
    op->channel_id = channel_id;
    op->done = done;
    wcom_exec(&op->base);
}
