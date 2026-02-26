#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Register WASI Preview 1 shim functions under "wasi_snapshot_preview1".
 */
int wendy_wasi_shim_init(void);

#ifdef __cplusplus
}
#endif
