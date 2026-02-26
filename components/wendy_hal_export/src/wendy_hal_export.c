#include "wendy_hal_export.h"
#include "esp_log.h"

static const char *TAG = "wendy_hal_export";

/* Forward-declare each module's registration function (defined in their own .c) */
#if CONFIG_WENDY_HAL_GPIO
int wendy_hal_export_gpio(void);
#endif
#if CONFIG_WENDY_HAL_I2C
int wendy_hal_export_i2c(void);
#endif
#if CONFIG_WENDY_HAL_TIMER
int wendy_hal_export_timer(void);
#endif
#if CONFIG_WENDY_HAL_NEOPIXEL
int wendy_hal_export_neopixel(void);
#endif

/* New subsystem registration functions */
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
#if CONFIG_WENDY_WASI_SHIM
#include "wendy_wasi_shim.h"
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

esp_err_t wendy_hal_export_init(void)
{
    int count = 0;
    int errors = 0;

    /* ── Callback subsystem (must be first) ───────────────────────────── */
#if CONFIG_WENDY_CALLBACK
    count++;
    if (wendy_callback_init() != ESP_OK) {
        ESP_LOGE(TAG, "callback init failed");
        errors++;
    }
#endif

    /* ── Original HAL exports ─────────────────────────────────────────── */
#if CONFIG_WENDY_HAL_GPIO
    count++;
    if (wendy_hal_export_gpio() != 0) {
        ESP_LOGE(TAG, "GPIO export registration failed");
        errors++;
    }
#endif

#if CONFIG_WENDY_HAL_I2C
    count++;
    if (wendy_hal_export_i2c() != 0) {
        ESP_LOGE(TAG, "I2C export registration failed");
        errors++;
    }
#endif

#if CONFIG_WENDY_HAL_TIMER
    count++;
    if (wendy_hal_export_timer() != 0) {
        ESP_LOGE(TAG, "Timer export registration failed");
        errors++;
    }
#endif

#if CONFIG_WENDY_HAL_NEOPIXEL
    count++;
    if (wendy_hal_export_neopixel() != 0) {
        ESP_LOGE(TAG, "NeoPixel export registration failed");
        errors++;
    }
#endif

    /* ── New subsystem exports ────────────────────────────────────────── */
#if CONFIG_WENDY_SYS
    count++;
    if (wendy_sys_export_init() != 0) {
        ESP_LOGE(TAG, "System export registration failed");
        errors++;
    }
#endif

#if CONFIG_WENDY_STORAGE
    count++;
    if (wendy_storage_export_init() != 0) {
        ESP_LOGE(TAG, "Storage export registration failed");
        errors++;
    }
#endif

#if CONFIG_WENDY_UART
    count++;
    if (wendy_uart_export_init() != 0) {
        ESP_LOGE(TAG, "UART export registration failed");
        errors++;
    }
#endif

#if CONFIG_WENDY_SPI
    count++;
    if (wendy_spi_export_init() != 0) {
        ESP_LOGE(TAG, "SPI export registration failed");
        errors++;
    }
#endif

#if CONFIG_WENDY_OTEL
    count++;
    if (wendy_otel_export_init() != 0) {
        ESP_LOGE(TAG, "OpenTelemetry export registration failed");
        errors++;
    }
#endif

#if CONFIG_WENDY_WASI_SHIM
    count++;
    if (wendy_wasi_shim_init() != 0) {
        ESP_LOGE(TAG, "WASI shim registration failed");
        errors++;
    }
#endif

#if CONFIG_WENDY_BLE
    count++;
    if (wendy_ble_export_init() != 0) {
        ESP_LOGE(TAG, "BLE export registration failed");
        errors++;
    }
#endif

#if CONFIG_WENDY_NET
    count++;
    if (wendy_net_export_init() != 0) {
        ESP_LOGE(TAG, "Networking export registration failed");
        errors++;
    }
#endif

#if CONFIG_WENDY_APP_USB
    count++;
    if (wendy_app_usb_export_init() != 0) {
        ESP_LOGE(TAG, "App USB export registration failed");
        errors++;
    }
#endif

    ESP_LOGI(TAG, "registered %d export modules (%d errors)", count, errors);
    return (errors == 0) ? ESP_OK : ESP_FAIL;
}
