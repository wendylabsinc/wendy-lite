// WendyCBridge.h — aggregates ESP-IDF and Wendy HAL C headers for Swift import.
// Imported in Swift via: import WendyC

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// ESP-IDF
#include "esp_err.h"
#include "esp_log.h"
#include "esp_partition.h"
#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

// Wendy HAL + subsystems
#include "wendy_hal.h"
#include "wendy_wasm.h"

#if CONFIG_WENDY_CALLBACK
#include "wendy_callback.h"
#endif

#if CONFIG_WENDY_SYS
#include "wendy_sys.h"
#endif

#if CONFIG_WENDY_STORAGE
#include "wendy_storage.h"
#endif

#if CONFIG_WENDY_UART
#include "wendy_uart.h"
#endif

#if CONFIG_WENDY_SPI
#include "wendy_spi.h"
#endif

#if CONFIG_WENDY_OTEL
#include "wendy_otel.h"
#endif

#if CONFIG_WENDY_BLE
#include "wendy_ble.h"
#endif

#if CONFIG_WENDY_NET
#include "wendy_net.h"
#endif

#if CONFIG_WENDY_APP_USB
#include "wendy_app_usb.h"
#endif

// Output callback fired by wendy_print
extern void wendy_wasmkit_handle_print(const char *buf, int len);

// FreeRTOS pdMS_TO_TICKS is a macro; expose as a C function so Swift can call it.
static inline uint32_t wendy_ms_to_ticks(uint32_t ms) {
    return (uint32_t)pdMS_TO_TICKS(ms);
}

// esp_log_write is variadic and unavailable in Embedded Swift.
// Use this non-variadic wrapper instead.
static inline void wendy_log(esp_log_level_t level, const char *tag, const char *msg) {
    esp_log_write(level, tag, "%s", msg);
}

// Output callback setter (defined in WasmKitBridge.c)
extern void wendy_wasmkit_set_output_cb(wendy_wasm_output_cb_t cb, void *ctx);

// ESP-IDF functions used directly from Swift (not in headers above)
#include "esp_timer.h"
#include "esp_system.h"
#include "esp_mac.h"

// WasmKit-callable public wrappers added to each subsystem component.
// Declared here so Swift can find them via the WendyC module.
#if CONFIG_WENDY_UART
#include "wendy_uart.h"
#endif
#if CONFIG_WENDY_SPI
#include "wendy_spi.h"
#endif
#if CONFIG_WENDY_STORAGE
#include "wendy_storage.h"
#endif
#if CONFIG_WENDY_OTEL
#include "wendy_otel.h"
#endif
