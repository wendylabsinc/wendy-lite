#pragma once
#include "esp_err.h"
#include <stdint.h>
esp_err_t esp_efuse_mac_get_default(uint8_t mac[6]);
