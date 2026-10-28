/* Lab SensorLink source: actual SoC temperature, no synthetic camera data. */
#include "driver/temperature_sensor.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "wendy_core_sensor.h"
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#define TEMPERATURE_CHANNEL 42
static temperature_sensor_handle_t sensor;
struct probe_stream {
    struct wcom_operation finish;
    int client;
    atomic_bool stop,pending;
    uint8_t sample[4];
};
/* The delegate, completion and finish operation all run on the com task. The
 * producer owns its context until it queues finish, then never touches it. */
static struct probe_stream *active;
static void frame_done(uint32_t channel)
{
    if (active && channel==TEMPERATURE_CHANNEL) atomic_store(&active->pending,false);
}
static void finish(struct wcom_operation *operation)
{
    struct probe_stream *stream=(struct probe_stream*)operation;
    (void)wcom_sensor_stream_end(stream->client,TEMPERATURE_CHANNEL);
    if (active==stream) active=NULL;
    free(stream);
}
static void produce(void *argument)
{
    struct probe_stream *stream=argument;
    wendy_core_sensor_stream_begin(stream->client,TEMPERATURE_CHANNEL);
    while (!atomic_load(&stream->stop)) {
        float celsius;
        if (temperature_sensor_get_celsius(sensor,&celsius)==ESP_OK) {
            uint32_t bits;memcpy(&bits,&celsius,sizeof bits);
            for (unsigned i=0;i<4;i++) stream->sample[i]=(uint8_t)(bits>>(8*i));
            atomic_store(&stream->pending,true);
            if (wendy_core_sensor_stream_try_push(stream->client,TEMPERATURE_CHANNEL,
                stream->sample,sizeof stream->sample,esp_timer_get_time(),frame_done)!=WendyComResult_WENDY_COM_RESULT_OK)
                atomic_store(&stream->pending,false);
            while (atomic_load(&stream->pending)) vTaskDelay(pdMS_TO_TICKS(10));
        }
        for (unsigned i=0;i<10 && !atomic_load(&stream->stop);i++) vTaskDelay(pdMS_TO_TICKS(100));
    }
    stream->finish.func=finish;wcom_exec(&stream->finish);
    vTaskDelete(NULL);
}
static enum wcom_sensor_link_result manifest(struct wcom_sensor_descriptor *out,
    size_t capacity,size_t *count)
{
    *count=0;
    if (capacity) {
        out[0]=(struct wcom_sensor_descriptor){.channel_id=TEMPERATURE_CHANNEL,
            .input_id=TEMPERATURE_CHANNEL,.name="chip-temperature",
            .format_kind=WCOM_SENSOR_FORMAT_SENSOR,.format.sensor={
                .schema="wendy.temperature.celsius.f32le.v1",.rate_hz=1,.sample_bytes=4}};
        *count=1;
    }
    return WCOM_SENSOR_LINK_OK;
}
static bool valid(const uint32_t *ids,size_t count)
{
    return !count || (ids && count==1 && ids[0]==TEMPERATURE_CHANNEL);
}
static enum wcom_sensor_link_result subscribe(int client,const uint32_t *ids,size_t count)
{
    if (!valid(ids,count)) return WCOM_SENSOR_LINK_FAIL;
    if (!count) return WCOM_SENSOR_LINK_OK;
    if (active) return active->client==client && !atomic_load(&active->stop)
        ? WCOM_SENSOR_LINK_OK : WCOM_SENSOR_LINK_BUSY;
    struct probe_stream *stream=calloc(1,sizeof *stream);
    if (!stream) return WCOM_SENSOR_LINK_BUSY;
    stream->client=client;atomic_init(&stream->stop,false);atomic_init(&stream->pending,false);
    active=stream;
    if (xTaskCreate(produce,"sensor-temp",3072,stream,3,NULL)!=pdPASS) {
        active=NULL;free(stream);return WCOM_SENSOR_LINK_BUSY;
    }
    return WCOM_SENSOR_LINK_OK;
}
static enum wcom_sensor_link_result unsubscribe(int client,const uint32_t *ids,size_t count)
{
    if (!valid(ids,count)) return WCOM_SENSOR_LINK_FAIL;
    if (count && active && active->client==client) atomic_store(&active->stop,true);
    return WCOM_SENSOR_LINK_OK;
}
static void disconnected(int client)
{
    if (active && active->client==client) atomic_store(&active->stop,true);
}
void wendy_net_sensor_probe_init(void)
{
    temperature_sensor_config_t config=TEMPERATURE_SENSOR_CONFIG_DEFAULT(10,80);
    esp_err_t result=temperature_sensor_install(&config,&sensor);
    if (result==ESP_OK) result=temperature_sensor_enable(sensor);
    if (result!=ESP_OK) {
        if (sensor) temperature_sensor_uninstall(sensor);
        sensor=NULL;ESP_LOGW("net_sensor_probe","SoC sensor unavailable: %s",esp_err_to_name(result));return;
    }
    static const struct wcom_sensor_link_delegate delegate={
        .on_sensor_link_get_manifest=manifest,.on_sensor_link_subscribe=subscribe,
        .on_sensor_link_unsubscribe=unsubscribe,.on_sensor_link_disconnected=disconnected};
    wendy_core_register_sensor_link_source(&delegate);
}
