#pragma once

#include "driver/i2c_master.h"

/* Camera SCCB and ES8389 share I2C0. Init/deinit run serially at startup. */
esp_err_t korvo_i2c_acquire(i2c_master_bus_handle_t *bus);
void korvo_i2c_release(void);
