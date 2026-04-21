#include "wendy_callback.h"

#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "esp_log.h"
#include "wasm_export.h"

static const char *TAG = "wendy_callback";

#define CALLBACK_QUEUE_LEN 16

static QueueHandle_t s_queue;
static uint32_t s_alloc_bitmap; /* bit per handler ID (1..32) */

static wasm_function_inst_t lookup_handler_function(wasm_module_inst_t module_inst)
{
    return wasm_runtime_lookup_function(module_inst, "wendy_handle_callback", NULL);
}

static void dispatch_event(wasm_exec_env_t exec_env,
                           wasm_module_inst_t module_inst,
                           wasm_function_inst_t handler_func,
                           wendy_callback_event_t evt)
{
    if (!handler_func) {
        return;
    }

    uint32_t argv[4] = { evt.handler_id, evt.arg0, evt.arg1, evt.arg2 };
    if (!wasm_runtime_call_wasm(exec_env, handler_func, 4, argv)) {
        const char *exc = wasm_runtime_get_exception(module_inst);
        ESP_LOGE(TAG, "callback dispatch failed (handler_id=%lu): %s",
                 (unsigned long)evt.handler_id, exc ? exc : "unknown");
        wasm_runtime_clear_exception(module_inst);
    }
}

/* Drain all queued events (plus optional first_evt) and return the count.
 * If handler_func is NULL the events are silently dequeued and dropped. */
static int dispatch_event_batch(wasm_exec_env_t exec_env,
                                wasm_module_inst_t module_inst,
                                wasm_function_inst_t handler_func,
                                const wendy_callback_event_t *first_evt)
{
    int count = 0;
    wendy_callback_event_t evt;

    if (first_evt) {
        dispatch_event(exec_env, module_inst, handler_func, *first_evt);
        count++;
    }

    while (xQueueReceive(s_queue, &evt, 0) == pdTRUE) {
        dispatch_event(exec_env, module_inst, handler_func, evt);
        count++;
    }

    return count;
}

esp_err_t wendy_callback_init(void)
{
    if (s_queue) {
        return ESP_OK;
    }
    s_queue = xQueueCreate(CALLBACK_QUEUE_LEN, sizeof(wendy_callback_event_t));
    if (!s_queue) {
        return ESP_ERR_NO_MEM;
    }
    s_alloc_bitmap = 0;
    ESP_LOGI(TAG, "callback subsystem initialized (queue=%d)", CALLBACK_QUEUE_LEN);
    return ESP_OK;
}

uint32_t wendy_callback_alloc(void)
{
    for (int i = 0; i < WENDY_CALLBACK_MAX_HANDLERS; i++) {
        if (!(s_alloc_bitmap & (1u << i))) {
            s_alloc_bitmap |= (1u << i);
            return (uint32_t)(i + 1); /* 1-based ID */
        }
    }
    ESP_LOGE(TAG, "no free handler IDs");
    return 0;
}

void wendy_callback_free(uint32_t handler_id)
{
    if (handler_id == 0 || handler_id > WENDY_CALLBACK_MAX_HANDLERS) {
        return;
    }
    s_alloc_bitmap &= ~(1u << (handler_id - 1));
}

esp_err_t wendy_callback_post(uint32_t handler_id,
                               uint32_t arg0, uint32_t arg1, uint32_t arg2)
{
    if (!s_queue) {
        return ESP_ERR_INVALID_STATE;
    }
    wendy_callback_event_t evt = {
        .handler_id = handler_id,
        .arg0 = arg0,
        .arg1 = arg1,
        .arg2 = arg2,
    };
    if (xQueueSend(s_queue, &evt, pdMS_TO_TICKS(10)) != pdTRUE) {
        ESP_LOGW(TAG, "callback queue full, dropping handler_id=%lu",
                 (unsigned long)handler_id);
        return ESP_ERR_TIMEOUT;
    }
    return ESP_OK;
}

esp_err_t wendy_callback_post_from_isr(uint32_t handler_id,
                                        uint32_t arg0, uint32_t arg1, uint32_t arg2)
{
    if (!s_queue) {
        return ESP_ERR_INVALID_STATE;
    }
    wendy_callback_event_t evt = {
        .handler_id = handler_id,
        .arg0 = arg0,
        .arg1 = arg1,
        .arg2 = arg2,
    };
    BaseType_t xHigherPriorityTaskWoken = pdFALSE;
    if (xQueueSendFromISR(s_queue, &evt, &xHigherPriorityTaskWoken) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }
    portYIELD_FROM_ISR(xHigherPriorityTaskWoken);
    return ESP_OK;
}

int wendy_callback_dispatch(void *exec_env_ptr, void *module_inst_ptr)
{
    if (!s_queue) {
        return 0;
    }

    wasm_exec_env_t exec_env = (wasm_exec_env_t)exec_env_ptr;
    wasm_module_inst_t module_inst = (wasm_module_inst_t)module_inst_ptr;

    wasm_function_inst_t handler_func = lookup_handler_function(module_inst);
    int count = dispatch_event_batch(exec_env, module_inst, handler_func, NULL);

    if (!handler_func) {
        if (count > 0) {
            ESP_LOGW(TAG, "dropped %d callbacks (no wendy_handle_callback export)", count);
        }
        return 0;
    }

    return count;
}

int wendy_callback_wait_and_dispatch(void *exec_env_ptr, void *module_inst_ptr, uint32_t timeout_ms)
{
    if (!s_queue) {
        return 0;
    }

    wasm_exec_env_t exec_env = (wasm_exec_env_t)exec_env_ptr;
    wasm_module_inst_t module_inst = (wasm_module_inst_t)module_inst_ptr;
    wasm_function_inst_t handler_func = lookup_handler_function(module_inst);

    TickType_t ticks = pdMS_TO_TICKS(timeout_ms);
    if (timeout_ms > 0 && ticks == 0) {
        ticks = 1;
    }

    wendy_callback_event_t first_evt;
    if (xQueueReceive(s_queue, &first_evt, ticks) != pdTRUE) {
        return 0;
    }

    int count = dispatch_event_batch(exec_env, module_inst, handler_func, &first_evt);

    if (!handler_func) {
        if (count > 0) {
            ESP_LOGW(TAG, "dropped %d callbacks (no wendy_handle_callback export)", count);
        }
        return 0;
    }

    return count;
}

void wendy_callback_deinit(void)
{
    if (s_queue) {
        vQueueDelete(s_queue);
        s_queue = NULL;
    }
    s_alloc_bitmap = 0;
}
