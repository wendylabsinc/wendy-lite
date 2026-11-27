#pragma once

#include "esp_err.h"

typedef struct {
    char version[32];
} esp_hosted_app_desc_t;

esp_err_t esp_hosted_get_coprocessor_app_desc(esp_hosted_app_desc_t *desc);
