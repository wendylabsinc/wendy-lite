#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
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

/* Each stream holds one slot from begin() until end() has run and its last
 * frame is done. The slot carries the stream's own begin, push and end
 * operations, so a stream never competes with others for queue space, and a
 * node is never queued twice: begin and end are queued once per slot, push
 * only while its pending flag is clear.
 *
 * state is the only field shared between tasks. A producer claims a FREE slot
 * with a compare-and-swap and publishes the ids with OPEN; push and end only
 * match OPEN slots. The com task runs operations in submission order, so the
 * begin and every push queued before end have run when end runs, and the
 * slot returns to FREE once the transport has released the last frame too. */
enum {
    SLOT_FREE = 0,  // no stream
    SLOT_CLAIMED,   // begin() is writing the ids
    SLOT_OPEN,      // push() and end() accepted
    SLOT_ENDING,    // end() queued
    SLOT_DRAINING,  // closed, the transport still holds the last frame
};

struct sensor_push_op {
    struct wcom_operation base;
    atomic_bool pending;
    const void *data;
    size_t size;
    uint64_t ts_us;
    wendy_core_sensor_done_t done;
    void (*legacy_done)(uint32_t channel_id);   // try_push()
};

struct sensor_slot {
    atomic_int state;
    int client_id;
    uint32_t channel_id;
    // Com task only: the frame the transport holds, and who to tell.
    bool frame_in_flight;
    wendy_core_sensor_done_t frame_done;
    void (*frame_legacy_done)(uint32_t channel_id);
    struct wcom_operation begin_op;
    struct wcom_operation end_op;
    wendy_core_sensor_done_t end_done;
    struct sensor_push_op push;
};

#define SLOT_OF(op, member) \
    ((struct sensor_slot *)((char *)(op) - offsetof(struct sensor_slot, member)))

static struct sensor_slot s_slots[WCOM_SENSOR_MAX_STREAMS];

static bool take_op(atomic_bool *pending)
{
    bool expected = false;
    return atomic_compare_exchange_strong(pending, &expected, true);
}

/* Any slot this stream holds, or only an OPEN one. */
static struct sensor_slot *find_slot(int client_id, uint32_t channel_id, bool open_only)
{
    for (size_t i = 0; i < WCOM_SENSOR_MAX_STREAMS; i++) {
        struct sensor_slot *slot = &s_slots[i];
        int state = atomic_load_explicit(&slot->state, memory_order_acquire);
        if (state == SLOT_FREE || state == SLOT_CLAIMED || (open_only && state != SLOT_OPEN))
            continue;
        if (slot->client_id == client_id && slot->channel_id == channel_id)
            return slot;
    }
    return NULL;
}

static void notify(int client_id, uint32_t channel_id, wendy_core_sensor_done_t done,
                   void (*legacy_done)(uint32_t channel_id), enum wendy_core_sensor_result result)
{
    if (done)
        done(client_id, channel_id, result);
    else if (legacy_done)
        legacy_done(channel_id);
}

static enum wendy_core_sensor_result from_wcom(WendyComResult result)
{
    if (result == WendyComResult_WENDY_COM_RESULT_OK)
        return WENDY_CORE_SENSOR_OK;
    // UNKNOWN_ERROR is the XIAO staging buffer out of memory: worth a retry.
    if (result == WendyComResult_WENDY_COM_RESULT_BUSY ||
        result == WendyComResult_WENDY_COM_RESULT_UNKNOWN_ERROR)
        return WENDY_CORE_SENSOR_BUSY;
    return WENDY_CORE_SENSOR_BAD_ARG;
}

static void stream_begin_exec(struct wcom_operation *base)
{
    struct sensor_slot *slot = SLOT_OF(base, begin_op);
    WendyComResult result = wcom_sensor_stream_begin(slot->client_id, slot->channel_id);
    if (result != WendyComResult_WENDY_COM_RESULT_OK)
        ESP_LOGW(TAG, "sensor stream begin refused on channel %" PRIu32 ": %d",
                 slot->channel_id, result);
}

static void frame_done_trampoline(uint32_t channel_id, void *ctx)
{
    struct sensor_slot *slot = ctx;
    int client_id = slot->client_id;
    wendy_core_sensor_done_t done = slot->frame_done;
    void (*legacy_done)(uint32_t channel_id) = slot->frame_legacy_done;
    slot->frame_in_flight = false;
    slot->frame_done = NULL;
    slot->frame_legacy_done = NULL;
    // The stream was closed while this frame was still on the transport.
    if (atomic_load_explicit(&slot->state, memory_order_relaxed) == SLOT_DRAINING)
        atomic_store_explicit(&slot->state, SLOT_FREE, memory_order_release);
    notify(client_id, channel_id, done, legacy_done, WENDY_CORE_SENSOR_OK);
}

static void stream_push_exec(struct wcom_operation *base)
{
    struct sensor_slot *slot = SLOT_OF(base, push.base);
    struct sensor_push_op *op = &slot->push;
    const void *data = op->data;
    size_t size = op->size;
    uint64_t ts_us = op->ts_us;
    wendy_core_sensor_done_t done = op->done;
    void (*legacy_done)(uint32_t channel_id) = op->legacy_done;
    atomic_store(&op->pending, false);

    // The transport still holds this stream's previous frame: wcom would say
    // BUSY too, and its callbacks must not be overwritten.
    WendyComResult result = WendyComResult_WENDY_COM_RESULT_BUSY;
    if (!slot->frame_in_flight) {
        // Set before the call, so a completion from inside it finds them.
        slot->frame_in_flight = true;
        slot->frame_done = done;
        slot->frame_legacy_done = legacy_done;
        result = wcom_sensor_stream_push(slot->client_id, slot->channel_id, data, size, ts_us,
                                         frame_done_trampoline, slot);
        if (result == WendyComResult_WENDY_COM_RESULT_OK)
            return;
        slot->frame_in_flight = false;
        slot->frame_done = NULL;
        slot->frame_legacy_done = NULL;
    }
    // Refused frames never reached the transport, so their buffers return to
    // the producer here.
    notify(slot->client_id, slot->channel_id, done, legacy_done, from_wcom(result));
}

static void stream_end_exec(struct wcom_operation *base)
{
    struct sensor_slot *slot = SLOT_OF(base, end_op);
    int client_id = slot->client_id;
    uint32_t channel_id = slot->channel_id;
    wendy_core_sensor_done_t done = slot->end_done;
    slot->end_done = NULL;
    // A frame waiting for its turn is released from inside this call; one
    // already queued to the transport completes later, through the trampoline.
    wcom_sensor_stream_end(client_id, channel_id);
    atomic_store_explicit(&slot->state, slot->frame_in_flight ? SLOT_DRAINING : SLOT_FREE,
                          memory_order_release);
    if (done)
        done(client_id, channel_id, WENDY_CORE_SENSOR_OK);
}

enum wendy_core_sensor_result wendy_core_sensor_stream_begin(int client_id, uint32_t channel_id)
{
    if (client_id < 0)
        return WENDY_CORE_SENSOR_BAD_ARG;
    if (find_slot(client_id, channel_id, false))
        return WENDY_CORE_SENSOR_BUSY;
    for (size_t i = 0; i < WCOM_SENSOR_MAX_STREAMS; i++) {
        struct sensor_slot *slot = &s_slots[i];
        int expected = SLOT_FREE;
        if (!atomic_compare_exchange_strong(&slot->state, &expected, SLOT_CLAIMED))
            continue;
        slot->client_id = client_id;
        slot->channel_id = channel_id;
        atomic_store(&slot->push.pending, false);
        slot->begin_op.func = stream_begin_exec;
        atomic_store_explicit(&slot->state, SLOT_OPEN, memory_order_release);
        wcom_exec(&slot->begin_op);
        return WENDY_CORE_SENSOR_OK;
    }
    return WENDY_CORE_SENSOR_BUSY;
}

static enum wendy_core_sensor_result queue_push(int client_id, uint32_t channel_id,
                                                const void *data, size_t size, uint64_t ts_us,
                                                wendy_core_sensor_done_t done,
                                                void (*legacy_done)(uint32_t channel_id))
{
    if (!data || size == 0)
        return WENDY_CORE_SENSOR_BAD_ARG;
    struct sensor_slot *slot = find_slot(client_id, channel_id, true);
    if (!slot)
        return WENDY_CORE_SENSOR_BAD_ARG;
    struct sensor_push_op *op = &slot->push;
    if (!take_op(&op->pending))
        return WENDY_CORE_SENSOR_BUSY;
    op->base.func = stream_push_exec;
    op->data = data;
    op->size = size;
    op->ts_us = ts_us;
    op->done = done;
    op->legacy_done = legacy_done;
    wcom_exec(&op->base);
    return WENDY_CORE_SENSOR_OK;
}

void wendy_core_sensor_stream_push(int client_id, uint32_t channel_id, const void *data,
                                   size_t size, uint64_t ts_us, wendy_core_sensor_done_t done)
{
    enum wendy_core_sensor_result result = queue_push(client_id, channel_id, data, size, ts_us,
                                                      done, NULL);
    if (result != WENDY_CORE_SENSOR_OK && done)
        done(client_id, channel_id, result);
}

WendyComResult wendy_core_sensor_stream_try_push(int client_id, uint32_t channel_id,
                                                const void *data, size_t size, uint64_t ts_us,
                                                void (*done)(uint32_t channel_id))
{
    switch (queue_push(client_id, channel_id, data, size, ts_us, NULL, done)) {
    case WENDY_CORE_SENSOR_OK:
        return WendyComResult_WENDY_COM_RESULT_OK;
    case WENDY_CORE_SENSOR_BUSY:
        return WendyComResult_WENDY_COM_RESULT_BUSY;
    default:
        return WendyComResult_WENDY_COM_RESULT_BAD_STATE;
    }
}

void wendy_core_sensor_stream_end(int client_id, uint32_t channel_id, wendy_core_sensor_done_t done)
{
    struct sensor_slot *slot = find_slot(client_id, channel_id, true);
    int expected = SLOT_OPEN;
    if (!slot || !atomic_compare_exchange_strong(&slot->state, &expected, SLOT_ENDING)) {
        ESP_LOGW(TAG, "sensor stream end on channel %" PRIu32 ": stream not open", channel_id);
        if (done)
            done(client_id, channel_id, WENDY_CORE_SENSOR_BAD_ARG);
        return;
    }
    slot->end_done = done;
    slot->end_op.func = stream_end_exec;
    wcom_exec(&slot->end_op);
}
