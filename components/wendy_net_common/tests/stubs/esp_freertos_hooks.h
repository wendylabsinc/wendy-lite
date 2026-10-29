#pragma once
#include <stdbool.h>
#include "freertos/FreeRTOS.h"
#define ESP_OK 0
int esp_register_freertos_idle_hook_for_cpu(bool (*)(void), UBaseType_t);
void esp_deregister_freertos_idle_hook_for_cpu(bool (*)(void), UBaseType_t);
