#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

typedef struct {
    uint32_t major1, minor1, patch1;
} esp_hosted_coprocessor_fwver_t;

int esp_hosted_connect_to_slave(void);
int esp_hosted_get_coprocessor_fwversion(esp_hosted_coprocessor_fwver_t *version);
esp_err_t esp_hosted_bt_controller_init(void);
esp_err_t esp_hosted_bt_controller_enable(void);
esp_err_t esp_hosted_bt_controller_disable(void);
esp_err_t esp_hosted_bt_controller_deinit(bool mem_release);
