#pragma once
#include "esp_err.h"

/* CDC 0 carries the physical WendyCom connection; CDC 1 carries diagnostics. */
esp_err_t mosaico_usb_management_start(void);
