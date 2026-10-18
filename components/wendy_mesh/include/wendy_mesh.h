#pragma once
#include "esp_err.h"
/* Starts one bounded retry task after Wi-Fi receives an address. The task
 * authenticates an enrolled UUID identity before creating its IPv6 interface. */
esp_err_t wendy_mesh_start(void);
