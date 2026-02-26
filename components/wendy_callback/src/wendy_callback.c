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

    /* Look up the WASM-side handler */
    wasm_function_inst_t handler_func =
        wasm_runtime_lookup_function(module_inst, "wendy_handle_callback", NULL);
    if (!handler_func) {
        /* Module doesn't export the callback handler — drain silently */
        wendy_callback_event_t evt;
        int dropped = 0;
        while (xQueueReceive(s_queue, &evt, 0) == pdTRUE) {
            dropped++;
        }
        if (dropped > 0) {
            ESP_LOGW(TAG, "dropped %d callbacks (no wendy_handle_callback export)", dropped);
        }
        return 0;
    }

    int count = 0;
    wendy_callback_event_t evt;
    while (xQueueReceive(s_queue, &evt, 0) == pdTRUE) {
        uint32_t argv[4] = { evt.handler_id, evt.arg0, evt.arg1, evt.arg2 };
        if (!wasm_runtime_call_wasm(exec_env, handler_func, 4, argv)) {
            const char *exc = wasm_runtime_get_exception(module_inst);
            ESP_LOGE(TAG, "callback dispatch failed (handler_id=%lu): %s",
                     (unsigned long)evt.handler_id, exc ? exc : "unknown");
            wasm_runtime_clear_exception(module_inst);
        }
        count++;
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
