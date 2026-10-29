#pragma once
#include "test_sdk.h"
#define ESP_ERR_INVALID_ARG 0x102
typedef int portMUX_TYPE;
#define portMUX_INITIALIZER_UNLOCKED 0
#define portENTER_CRITICAL(lock) ((void)(lock))
#define portEXIT_CRITICAL(lock) ((void)(lock))
struct ble_npl_event {void (*callback)(struct ble_npl_event *);void *argument;};
static inline void ble_npl_event_init(struct ble_npl_event *event,void (*callback)(struct ble_npl_event *),void *argument)
{event->callback=callback;event->argument=argument;}
static inline void ble_npl_event_deinit(struct ble_npl_event *event){memset(event,0,sizeof *event);}
static inline void *nimble_port_get_dflt_eventq(void){return (void *)1;}
static inline void ble_npl_eventq_put(void *queue,struct ble_npl_event *event)
{assert(queue==(void*)1);if(event->callback)event->callback(event);}
typedef void *esp_timer_handle_t;
typedef struct {void (*callback)(void *);void *arg;const char *name;} esp_timer_create_args_t;
static inline esp_err_t esp_timer_create(const esp_timer_create_args_t *args,esp_timer_handle_t *out)
{(void)args;*out=malloc(1);return *out ? ESP_OK:ESP_ERR_NO_MEM;}
static inline esp_err_t esp_timer_delete(esp_timer_handle_t timer){free(timer);return ESP_OK;}
static inline esp_err_t esp_timer_stop(esp_timer_handle_t timer){(void)timer;return ESP_OK;}
static uint64_t test_timer_period;
static unsigned test_timer_restarts;
static inline esp_err_t esp_timer_restart(esp_timer_handle_t timer,uint64_t period)
{assert(timer);test_timer_period=period;test_timer_restarts++;return ESP_OK;}
static inline esp_err_t esp_timer_start_periodic(esp_timer_handle_t timer,uint64_t period)
{(void)timer;test_timer_period=period;return ESP_OK;}
static inline int ble_gap_adv_set_data(const uint8_t *data,size_t size)
{(void)data;assert(size<=31);return 0;}

#if !WENDY_BLE_IO_DISPATCH_TEST
static int64_t test_now_us;
static inline int64_t esp_timer_get_time(void){return test_now_us;}
#endif
