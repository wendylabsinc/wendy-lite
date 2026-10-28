/* Actual WendyCom framing/command/SensorLink code, driven as the independent
 * plaintext application domain by a finite host outer loop. */
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <unistd.h>
#include "esp_vfs_eventfd.h"
static int fixture_eventfd(unsigned initial,int flags){(void)initial;(void)flags;return 8;}
static ssize_t fixture_event_read(int fd,void *out,size_t size){(void)fd;memset(out,0,size);return (ssize_t)size;}
static ssize_t fixture_event_write(int fd,const void *in,size_t size){(void)fd;(void)in;return (ssize_t)size;}
#define eventfd fixture_eventfd
#define read fixture_event_read
#define write fixture_event_write
#define _links transport_links
#define TAG transport_tag
#include "../../wendy_com/src/wendy_com_link.c"
#undef _links
#undef TAG
#undef eventfd
#undef read
#undef write
#include "../../wendy_com/src/wendy_com_agent.c"
#define TAG command_tag
#include "../../wendy_com/src/wendy_com_cmd.c"
#undef TAG
#include "wendy_com_sensor.h"
static unsigned manifest_calls,subscriptions,frame_done,connections;
#ifndef WENDY_COMPOSED_SAMPLE_BYTES
#define WENDY_COMPOSED_SAMPLE_BYTES 6000
#endif
static uint8_t samples[WENDY_COMPOSED_SAMPLE_BYTES];
static char sensor_name[700];
extern enum wcom_link_permission composed_expected_permission;
ssize_t wendy_com_uart_read(wendy_com_uart_t *uart,void *data,size_t size){return -1;}
ssize_t wendy_com_uart_write(wendy_com_uart_t *uart,const void *data,size_t size){return -1;}
int wendy_com_uart_get_fd(wendy_com_uart_t *uart){return uart->fd;}
int64_t wendy_com_uart_auto_close_delay(wendy_com_uart_t *uart){return -1;}
void wcom_stdio_pump_client_disconnected(int id){}
WendyComResult wcom_stdio_pump_attach(int id,uint32_t event,uint32_t duration,bool blocking){return WendyComResult_WENDY_COM_RESULT_OK;}
WendyComResult wcom_stdio_pump_detach(int id,uint32_t event){return WendyComResult_WENDY_COM_RESULT_OK;}
size_t wendy_stdio_put_stdin_data(const void *data,size_t size){return size;}
void wendy_conf_enrollment_identity(char tenant[37],char device[65]){tenant[0]=device[0]=0;}
void wendy_pki_builtin_trust(bool *ready,bool *tsa_ready){*ready=*tsa_ready=false;}
esp_err_t wendy_pki_challenge(bool status,char nonce[65],bool *enrolled){*enrolled=false;return ESP_OK;}
esp_err_t wendy_pki_reset(const char *device,const char *nonce){return ESP_OK;}
esp_err_t wendy_pki_sync_time(const char *server,const uint8_t *reply,size_t size,bool *synchronized,int64_t *seconds){return ESP_OK;}
static enum wcom_sensor_link_result manifest(struct wcom_sensor_descriptor *sensors,size_t maximum,size_t *count)
{
    assert(maximum);manifest_calls++;*count=1;memset(sensors,0,sizeof *sensors);
    sensors->name=sensor_name;sensors->channel_id=7;sensors->input_id=1;
    sensors->format_kind=WCOM_SENSOR_FORMAT_SENSOR;sensors->format.sensor.schema="f32";
    sensors->format.sensor.rate_hz=10;sensors->format.sensor.sample_bytes=4;
    return WCOM_SENSOR_LINK_OK;
}
static void sample_done(uint32_t channel){assert(channel==7);frame_done++;}
static enum wcom_sensor_link_result subscribe_samples(int client,const uint32_t *channels,size_t count)
{
    assert(count==1 && channels[0]==7);subscriptions++;
    assert(wcom_sensor_stream_begin(client,7)==WendyComResult_WENDY_COM_RESULT_OK);
    assert(wcom_sensor_stream_push(client,7,samples,sizeof samples,123456,sample_done)==WendyComResult_WENDY_COM_RESULT_OK);
    return WCOM_SENSOR_LINK_OK;
}
static enum wcom_sensor_link_result unsubscribe_samples(int client,const uint32_t *channels,size_t count)
{assert(count==1 && channels[0]==7);assert(wcom_sensor_stream_end(client,7)==WendyComResult_WENDY_COM_RESULT_OK);return WCOM_SENSOR_LINK_OK;}
static void disconnected(int client){}
static void observe(struct wcom_state_change_handler *handler,int id,enum wcom_link_state state)
{
    if(state==WCOM_LINK_STATE_CONNECTED){assert(wcom_link_get_permission(id)==composed_expected_permission);connections++;}
}
void composed_com_init(void)
{
    _wakeup_efd=8;
    memset(sensor_name,'s',sizeof sensor_name-1);
    for(unsigned i=0;i<sizeof samples;i++)samples[i]=(uint8_t)(i*13);
    static struct wcom_state_change_handler observer={.func=observe},agent={.func=_on_link_state_changed};
    wcom_add_state_change_handler(&observer);wcom_add_state_change_handler(&agent);
    static const struct wcom_sensor_link_delegate sensors={.on_sensor_link_get_manifest=manifest,
        .on_sensor_link_subscribe=subscribe_samples,.on_sensor_link_unsubscribe=unsubscribe_samples,
        .on_sensor_link_disconnected=disconnected};
    wcom_cmd_set_sensor_link_delegate(&sensors);
}
void composed_com_poll(void)
{
    /* Same FIFO queue ownership and production RX/TX handlers as _main. The
     * host outer driver chooses when this separate application owner runs. */
    struct wcom_operation *op=atomic_exchange_explicit(&_op_queue_head,NULL,memory_order_acquire),*list=NULL;
    while(op){struct wcom_operation *next=op->next;op->next=list;list=op;op=next;}
    while(list){struct wcom_operation *next=list->next;list->func(list);list=next;}
    for(unsigned i=0;i<WCOM_LINK_COUNT;i++){
        struct wcom_link *link=&transport_links[i];
        if(link->state!=WCOM_LINK_STATE_CONNECTED)continue;
        if(link->rx_chunk_first && link->ops->can_read(link->stream_ctx))_link_do_rx(link);
        if(link->state==WCOM_LINK_STATE_CONNECTED && link->tx_chunk_first && link->ops->can_write(link->stream_ctx))_link_do_tx(link);
    }
}
void composed_com_check(void)
{assert(connections==1 && manifest_calls==1 && subscriptions==1 && frame_done==1);}
