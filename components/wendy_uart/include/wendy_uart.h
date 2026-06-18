#pragma once

#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Register UART host functions with the WASM runtime.
 */
int wendy_uart_export_init(void);

/* WasmKit-backend public API — same semantics, no wasm_exec_env_t */
int wendy_uart_guest_open(int port, int tx, int rx, int baud);
int wendy_uart_guest_close(int port);
int wendy_uart_guest_write(int port, const uint8_t *data, int len);
int wendy_uart_guest_read(int port, uint8_t *buf, int len);
int wendy_uart_guest_available(int port);
int wendy_uart_guest_flush(int port);
int wendy_uart_guest_set_on_receive(int port, uint32_t handler_id);

#ifdef __cplusplus
}
#endif
