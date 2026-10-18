#pragma once

#include "esp_err.h"

// Called once after the Wendy services have started. Only linked in benchmark builds.
esp_err_t wendy_benchmark_start(void);
