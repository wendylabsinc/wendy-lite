#pragma once

/* Keeps ESP32-S3 ROM printf (ets_printf) off the USB Serial/JTAG peripheral.
 * Both functions are no-ops on other targets. */

#ifdef __cplusplus
extern "C" {
#endif

/* Pins ROM printf output to UART0. Call before anything claims USB Serial/JTAG. */
void wendy_usj_rom_print_usb_disable(void);

/* Logs the ROM print state seen by wendy_usj_rom_print_usb_disable() and the current one.
 * Call once the log channel is up. Temporary diagnostic, safe to delete. */
void wendy_usj_rom_print_report(void);

#ifdef __cplusplus
}
#endif
