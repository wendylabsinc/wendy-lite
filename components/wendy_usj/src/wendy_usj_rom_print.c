#include "wendy_usj_rom_print.h"

#include "sdkconfig.h"

#if CONFIG_IDF_TARGET_ESP32S3

#include <stdbool.h>
#include <stdint.h>

#include "esp_log.h"
#include "esp_rom_uart.h"
#include "rom/ets_sys.h"

/*
 * Raw ROM output bypasses stdio entirely and, when it lands on USB Serial/JTAG,
 * collides with wendy_usj, which owns that peripheral -- the two streams
 * interleave mid-line.
 *
 * On Wendy Lite, stdout and logs are normally captured by wendy_stdio (which
 * owns the /dev/console VFS) and wendy_com (which hooks esp_log_set_vprintf).
 * ets_printf() bypasses both. This was first seen with the esp32-camera driver,
 * which uses ets_printf for its DMA-path warnings ("cam_hal: FB-OVF") because
 * those run where blocking on stdio is unsafe.
 *
 * The ROM's uart_tx_one_char() has *two* independent routes to USB, so both have
 * to be closed:
 *
 *   a4 = ets_get_printf_channel()
 *   if (g_usb_print) { tx(4, c); if (a4 == 4) return; }   // 4 = USB Serial/JTAG
 *   if (g_uart_print)  tx(a4, c);
 *
 * 1. g_usb_print is a ROM flag that unconditionally mirrors every char to USB.
 *    IDF sets it (and g_uart_print) to true in esp_rom_install_uart_printf() as
 *    a workaround for chips where ROM logging was disabled via eFuse, so it is
 *    on regardless of CONFIG_ESP_CONSOLE_*. This is the route that was actually
 *    active here. Clearing it leaves g_uart_print alone, so ROM output still
 *    reaches the selected channel.
 *
 * 2. That selected channel can itself be USB. With CONFIG_ESP_CONSOLE_UART_DEFAULT
 *    the bootloader never calls esp_rom_output_set_as_console() -- that call is
 *    inside #if CONFIG_ESP_CONSOLE_UART_CUSTOM -- so the channel keeps whatever
 *    the ROM picked when the chip booted over USB. It measured 0 (UART0) on this
 *    board, but forcing it costs nothing and covers the case where it is not.
 *
 * This also covers the panic handler and early-boot logs, which share the same
 * ROM channel. g_usb_print is a raw ROM symbol, PROVIDEd by esp32s3.rom.ld
 * rather than declared in any header -- hence the externs below.
 *
 * The C2 and C3 ROMs expose the same pair of flags and take the same patched
 * esp_rom_install_uart_printf() path, so the guard above can be widened if this
 * ever targets one of those.
 */
extern bool g_usb_print;
extern bool g_uart_print;

static uint8_t s_usb_print_was;
static uint8_t s_uart_print_was;
static uint8_t s_channel_was;

void wendy_usj_rom_print_usb_disable(void)
{
    s_usb_print_was = g_usb_print;
    s_uart_print_was = g_uart_print;
    s_channel_was = ets_get_printf_channel();

    g_usb_print = false;
    esp_rom_output_set_as_console(0);
}

void wendy_usj_rom_print_report(void)
{
    ESP_LOGI("rom_print", "before: usb=%u uart=%u channel=%u -- now: usb=%u channel=%u",
             s_usb_print_was, s_uart_print_was, s_channel_was,
             (unsigned)g_usb_print, ets_get_printf_channel());
}

#else // !CONFIG_IDF_TARGET_ESP32S3

void wendy_usj_rom_print_usb_disable(void) {}
void wendy_usj_rom_print_report(void) {}

#endif
