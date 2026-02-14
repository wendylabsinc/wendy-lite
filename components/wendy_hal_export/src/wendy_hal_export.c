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

esp_err_t wendy_hal_export_init(void)
{
    int count = 0;
    int errors = 0;

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

    ESP_LOGI(TAG, "registered %d HAL export modules (%d errors)", count, errors);
    return (errors == 0) ? ESP_OK : ESP_FAIL;
}
