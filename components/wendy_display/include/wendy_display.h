#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Start the Korvo-1 SUB3 LCD status screen and its one-second refresh task.
 *
 * Call after core initialization from task context. A successful repeated
 * call is a no-op. Initialization failures release allocated resources and
 * can be retried; callers should log the error and continue booting.
 * Available when CONFIG_WENDY_DISPLAY_ESP32S31_KORVO_1 is enabled.
 */
esp_err_t wendy_display_start(void);

#ifdef __cplusplus
}
#endif
