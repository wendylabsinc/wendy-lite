#pragma once
#include "esp_err.h"

void mosaico_diagnostics_start(void);
/* Stage strings must have static lifetime. Never include enrollment data. */
void mosaico_diagnostics_stage(const char *stage, esp_err_t error);
