#include "wendy_display.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>

#include "esp_heap_caps.h"
#include "esp_lcd_panel_ops.h"
#include "esp_lcd_panel_rgb.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "wendy_wifi.h"

enum { WIDTH = 800, HEIGHT = 480 };
#define RGB565(r, g, b) ((uint16_t)((((r) & 0xf8) << 8) | (((g) & 0xfc) << 3) | ((b) >> 3)))

static const char *TAG = "wendy_display";
static const uint16_t BG = RGB565(9, 17, 29);
static const uint16_t CARD = RGB565(18, 32, 48);
static const uint16_t WHITE = RGB565(235, 244, 249);
static const uint16_t MUTED = RGB565(136, 159, 178);
static const uint16_t CYAN = RGB565(67, 218, 214);
static const uint16_t GREEN = RGB565(121, 226, 171);
static const uint16_t AMBER = RGB565(244, 192, 108);

/* Five columns by seven rows, with the left pixel in bit 4. */
static const uint8_t LETTERS[26][7] = {
    {14, 17, 17, 31, 17, 17, 17}, /* A */
    {30, 17, 17, 30, 17, 17, 30}, /* B */
    {14, 17, 16, 16, 16, 17, 14}, /* C */
    {30, 17, 17, 17, 17, 17, 30}, /* D */
    {31, 16, 16, 30, 16, 16, 31}, /* E */
    {31, 16, 16, 30, 16, 16, 16}, /* F */
    {14, 17, 16, 23, 17, 17, 15}, /* G */
    {17, 17, 17, 31, 17, 17, 17}, /* H */
    {14, 4, 4, 4, 4, 4, 14},     /* I */
    {7, 2, 2, 2, 18, 18, 12},    /* J */
    {17, 18, 20, 24, 20, 18, 17}, /* K */
    {16, 16, 16, 16, 16, 16, 31}, /* L */
    {17, 27, 21, 21, 17, 17, 17}, /* M */
    {17, 25, 21, 19, 17, 17, 17}, /* N */
    {14, 17, 17, 17, 17, 17, 14}, /* O */
    {30, 17, 17, 30, 16, 16, 16}, /* P */
    {14, 17, 17, 17, 21, 18, 13}, /* Q */
    {30, 17, 17, 30, 20, 18, 17}, /* R */
    {15, 16, 16, 14, 1, 1, 30},   /* S */
    {31, 4, 4, 4, 4, 4, 4},      /* T */
    {17, 17, 17, 17, 17, 17, 14}, /* U */
    {17, 17, 17, 17, 17, 10, 4},  /* V */
    {17, 17, 17, 21, 21, 21, 10}, /* W */
    {17, 17, 10, 4, 10, 17, 17},  /* X */
    {17, 17, 10, 4, 4, 4, 4},     /* Y */
    {31, 1, 2, 4, 8, 16, 31},    /* Z */
};
static const uint8_t DIGITS[10][7] = {
    {14, 17, 19, 21, 25, 17, 14},
    {4, 12, 4, 4, 4, 4, 14},
    {14, 17, 1, 2, 4, 8, 31},
    {30, 1, 1, 14, 1, 1, 30},
    {2, 6, 10, 18, 31, 2, 2},
    {31, 16, 16, 30, 1, 1, 30},
    {14, 16, 16, 30, 17, 17, 14},
    {31, 1, 2, 4, 8, 8, 8},
    {14, 17, 17, 14, 17, 17, 14},
    {14, 17, 17, 15, 1, 1, 14},
};

typedef struct {
    esp_lcd_panel_handle_t panel;
    uint16_t *pixels;
} display_t;

static display_t s_display;
/* 0: stopped, 1: initializing, 2: running. */
static atomic_int s_state;

static void fill_rect(display_t *display, int x, int y, int w, int h, uint16_t color)
{
    int right = x + w;
    int bottom = y + h;
    if (x < 0) x = 0;
    if (y < 0) y = 0;
    if (right > WIDTH) right = WIDTH;
    if (bottom > HEIGHT) bottom = HEIGHT;
    for (int row = y; row < bottom; ++row) {
        for (int col = x; col < right; ++col) {
            display->pixels[row * WIDTH + col] = color;
        }
    }
}

static const uint8_t *glyph(char c)
{
    static const uint8_t blank[7] = {0};
    static const uint8_t dash[7] = {0, 0, 0, 14, 0, 0, 0};
    static const uint8_t slash[7] = {1, 1, 2, 4, 8, 16, 16};
    static const uint8_t colon[7] = {0, 4, 4, 0, 4, 4, 0};
    static const uint8_t dot[7] = {0, 0, 0, 0, 0, 4, 4};
    if (c >= 'A' && c <= 'Z') return LETTERS[c - 'A'];
    if (c >= '0' && c <= '9') return DIGITS[c - '0'];
    switch (c) {
        case '-': return dash;
        case '/': return slash;
        case ':': return colon;
        case '.': return dot;
        default: return blank;
    }
}

static void text(display_t *display, int x, int y, const char *value, int scale, uint16_t color)
{
    for (; *value && x < WIDTH; ++value, x += 6 * scale) {
        const uint8_t *rows = glyph(*value);
        for (int row = 0; row < 7; ++row) {
            for (int col = 0; col < 5; ++col) {
                if (rows[row] & (1u << (4 - col))) {
                    fill_rect(display, x + col * scale, y + row * scale, scale, scale, color);
                }
            }
        }
    }
}

static void draw_static(display_t *display)
{
    fill_rect(display, 0, 0, WIDTH, HEIGHT, BG);
    fill_rect(display, 40, 110, 720, 2, CYAN);
    text(display, 40, 36, "WENDY", 7, WHITE);
    text(display, 628, 53, "KORVO / 01", 2, MUTED);

    fill_rect(display, 40, 146, 12, 12, GREEN);
    text(display, 68, 139, "NATIVE READY", 4, GREEN);
    text(display, 40, 191, "ESP32-S31 / KORVO-1", 2, MUTED);

    const int cards[] = {40, 288, 536};
    const char *labels[] = {"UPTIME", "MEMORY", "WI-FI"};
    const char *details[] = {"SINCE BOOT", "FREE PSRAM", "NETWORK"};
    for (int i = 0; i < 3; ++i) {
        fill_rect(display, cards[i], 249, 224, 145, CARD);
        fill_rect(display, cards[i], 249, 224, 2, RGB565(37, 59, 77));
        text(display, cards[i] + 20, 273, labels[i], 2, MUTED);
        text(display, cards[i] + 20, 357, details[i], 2, MUTED);
    }
    text(display, 40, 435, "WENDY LITE / NATIVE FIRMWARE", 2, MUTED);
    text(display, 712, 435, "LIVE", 2, MUTED);
}

static void draw_status(display_t *display)
{
    uint64_t seconds = (uint64_t)esp_timer_get_time() / 1000000;
    uint64_t hours = seconds / 3600;
    char uptime[24];
    if (hours < 100) {
        snprintf(uptime, sizeof(uptime), "%02u:%02u:%02u",
                 (unsigned)hours, (unsigned)(seconds / 60 % 60), (unsigned)(seconds % 60));
    } else {
        snprintf(uptime, sizeof(uptime), "%" PRIu64 "D %02uH", seconds / 86400, (unsigned)(hours % 24));
    }

    size_t free_psram = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
    unsigned tenths_mib = (unsigned)((uint64_t)free_psram * 10 / (1024 * 1024));
    char memory[24];
    snprintf(memory, sizeof(memory), "%u.%u MIB", tenths_mib / 10, tenths_mib % 10);
    bool connected = wendy_wifi_is_connected();

    /* Only the values and heartbeat change. The header and cards stay intact. */
    fill_rect(display, 60, 307, 184, 32, CARD);
    fill_rect(display, 308, 307, 184, 32, CARD);
    fill_rect(display, 556, 307, 184, 32, CARD);
    text(display, 60, 313, uptime, 3, WHITE);
    text(display, 308, 313, memory, 3, WHITE);
    text(display, 556, 313, connected ? "ONLINE" : "OFFLINE", 3, connected ? GREEN : AMBER);

    fill_rect(display, 684, 434, 14, 14, seconds & 1 ? CYAN : RGB565(31, 99, 108));
    fill_rect(display, 688, 438, 6, 6, BG);
}

static esp_err_t flush(display_t *display)
{
    /* The driver's own framebuffer is recognized by pointer. No copy occurs;
     * draw_bitmap writes back its CPU cache before direct DMA reads PSRAM. */
    return esp_lcd_panel_draw_bitmap(display->panel, 0, 0, WIDTH, HEIGHT, display->pixels);
}

static void status_task(void *arg)
{
    display_t *display = arg;
    TickType_t wake = xTaskGetTickCount();
    for (;;) {
        vTaskDelayUntil(&wake, pdMS_TO_TICKS(1000));
        draw_status(display);
        esp_err_t err = flush(display);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "Status refresh failed: %s", esp_err_to_name(err));
        }
    }
}

esp_err_t wendy_display_start(void)
{
    int expected = 0;
    if (!atomic_compare_exchange_strong(&s_state, &expected, 1)) {
        return expected == 2 ? ESP_OK : ESP_ERR_INVALID_STATE;
    }

    const esp_lcd_rgb_panel_config_t config = {
        .clk_src = LCD_CLK_SRC_PLL160M,
        .timings = {
            .pclk_hz = 18000000,
            .h_res = WIDTH,
            .v_res = HEIGHT,
            .hsync_pulse_width = 40,
            .hsync_back_porch = 40,
            .hsync_front_porch = 48,
            .vsync_pulse_width = 23,
            .vsync_back_porch = 32,
            .vsync_front_porch = 13,
            .flags.pclk_active_neg = true,
        },
        .data_width = 16,
        .in_color_format = LCD_COLOR_FMT_RGB565,
        .out_color_format = LCD_COLOR_FMT_RGB565,
        .num_fbs = 1,
        .bounce_buffer_size_px = 0,
        .dma_burst_size = 64,
        .hsync_gpio_num = 44,
        .vsync_gpio_num = 45,
        .de_gpio_num = 43,
        .pclk_gpio_num = 40,
        /* SUB3 pulls DISP and backlight enable high locally. GPIO38 belongs
         * to the camera module, despite the BSP's older DISP assignment. */
        .disp_gpio_num = -1,
        .data_gpio_nums = {8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 33, 34, 35, 36},
        .flags.fb_in_psram = true,
    };

    void *framebuffer = NULL;
    esp_err_t err = esp_lcd_new_rgb_panel(&config, &s_display.panel);
    if (err != ESP_OK) goto fail;
    err = esp_lcd_rgb_panel_get_frame_buffer(s_display.panel, 1, &framebuffer);
    if (err != ESP_OK) goto fail;
    s_display.pixels = framebuffer;
    err = esp_lcd_panel_reset(s_display.panel);
    if (err != ESP_OK) goto fail;
    err = esp_lcd_panel_init(s_display.panel);
    if (err != ESP_OK) goto fail;

    draw_static(&s_display);
    draw_status(&s_display);
    err = flush(&s_display);
    if (err != ESP_OK) goto fail;
    if (xTaskCreate(status_task, "wendy_display", 4096, &s_display, 1, NULL) != pdPASS) {
        err = ESP_ERR_NO_MEM;
        goto fail;
    }
    atomic_store(&s_state, 2);
    ESP_LOGI(TAG, "Korvo-1 LCD ready: 800x480 RGB565, one PSRAM framebuffer");
    return ESP_OK;

fail:
    if (s_display.panel) {
        esp_lcd_panel_del(s_display.panel);
    }
    s_display = (display_t){0};
    atomic_store(&s_state, 0);
    return err;
}
