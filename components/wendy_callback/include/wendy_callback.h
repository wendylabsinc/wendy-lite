#pragma once

#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum concurrent handler IDs */
#define WENDY_CALLBACK_MAX_HANDLERS 32

/** Callback event posted to the dispatch queue */
typedef struct {
    uint32_t handler_id;
    uint32_t arg0;
    uint32_t arg1;
    uint32_t arg2;
} wendy_callback_event_t;

/**
 * Initialize the callback subsystem (creates the FreeRTOS queue).
 * @return ESP_OK on success
 */
esp_err_t wendy_callback_init(void);

/**
 * Allocate a new handler ID.
 * @return handler ID (>0) on success, 0 on failure
 */
uint32_t wendy_callback_alloc(void);

/**
 * Free a handler ID.
 * @param handler_id  ID returned by wendy_callback_alloc()
 */
void wendy_callback_free(uint32_t handler_id);

/**
 * Post a callback event to the dispatch queue (ISR-safe version available).
 * Called from native code (timer callbacks, GPIO ISRs, BLE events, etc.).
 * @param handler_id  Target handler
 * @param arg0        Argument 0
 * @param arg1        Argument 1
 * @param arg2        Argument 2
 * @return ESP_OK on success, ESP_ERR_TIMEOUT if queue full
 */
esp_err_t wendy_callback_post(uint32_t handler_id,
                               uint32_t arg0, uint32_t arg1, uint32_t arg2);

/**
 * Post from ISR context.
 */
esp_err_t wendy_callback_post_from_isr(uint32_t handler_id,
                                        uint32_t arg0, uint32_t arg1, uint32_t arg2);

/**
 * Drain the callback queue, dispatching each event to the WASM module's
 * exported `wendy_handle_callback(handler_id, arg0, arg1, arg2)`.
 * Must be called from the WASM thread context.
 * @param exec_env  Current WASM execution environment
 * @param module_inst  Current WASM module instance
 * @return number of callbacks dispatched
 */
int wendy_callback_dispatch(void *exec_env, void *module_inst);

/**
 * Shut down the callback subsystem.
 */
void wendy_callback_deinit(void);

#ifdef __cplusplus
}
#endif
