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
