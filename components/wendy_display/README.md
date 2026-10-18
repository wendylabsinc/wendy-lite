# Korvo-1 LCD status

`CONFIG_WENDY_DISPLAY_ESP32S31_KORVO_1` enables a native 800×480 status
screen on the ESP32-S31-Korvo-1 SUB3 LCD. Call `wendy_display_start()` after
core initialization; log errors and continue booting if the display cannot
start. Repeated calls after a successful start do nothing.

The screen shows uptime, free PSRAM, Wi-Fi state, and a one-second heartbeat.
It uses a compact bitmap font and one 750 KiB RGB565 PSRAM framebuffer.
Only the value fields and heartbeat are repainted each second. ESP-IDF's
`draw_bitmap` synchronizes the framebuffer cache for direct DMA. There is
no LVGL, touch handling, or additional external component dependency.

The SUB3 panel uses GPIO8–19 and GPIO33–36 for RGB565 data, GPIO40 for PCLK,
GPIO43 for DE, GPIO44 for HSYNC, and GPIO45 for VSYNC. DISP and backlight
enable are pulled high on SUB3; GPIO38 is left untouched because the camera
module shares that signal. The 18 MHz pixel clock and porch timings follow
the Espressif Korvo BSP. Bounce buffers and cache-safe RGB interrupts are
not enabled, so rendering does not add a PSRAM-copy interrupt during flash
cache suspension.
