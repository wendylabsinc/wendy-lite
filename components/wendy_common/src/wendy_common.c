#include "wendy_common.h"
#include "esp_vfs_eventfd.h"
#include "esp_log.h"
#include <stdatomic.h>
#include <stdbool.h>

static const char *TAG = "wendy_common";

void wendy_common_init_eventfd(void)
{
    static atomic_flag lock = ATOMIC_FLAG_INIT;
    static atomic_bool initialized = false;

    if (initialized)
        return;

    while (atomic_flag_test_and_set_explicit(&lock, memory_order_acquire));

    if (!initialized) {
        esp_vfs_eventfd_config_t cfg = ESP_VFS_EVENTD_CONFIG_DEFAULT();
        esp_err_t err = esp_vfs_eventfd_register(&cfg);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "esp_vfs_eventfd_register: %s (continuing)",
                        esp_err_to_name(err));
        }
        initialized = true;
    }

    atomic_flag_clear_explicit(&lock, memory_order_release);
}
