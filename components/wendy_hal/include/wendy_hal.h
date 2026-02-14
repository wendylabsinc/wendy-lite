#pragma once

#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── GPIO ───────────────────────────────────────────────────────────── */

typedef enum {
    WENDY_GPIO_MODE_INPUT       = 0,
    WENDY_GPIO_MODE_OUTPUT      = 1,
    WENDY_GPIO_MODE_INPUT_OUTPUT = 2,
} wendy_gpio_mode_t;

typedef enum {
    WENDY_GPIO_PULL_NONE = 0,
    WENDY_GPIO_PULL_UP   = 1,
    WENDY_GPIO_PULL_DOWN = 2,
} wendy_gpio_pull_t;

/**
 * Configure a GPIO pin.
 * @param pin   GPIO number
 * @param mode  Direction
 * @param pull  Pull-up/down configuration
 * @return 0 on success, negative on error
 */
int wendy_hal_gpio_configure(int pin, wendy_gpio_mode_t mode, wendy_gpio_pull_t pull);

/**
 * Read a GPIO input level.
 * @return 0 or 1, or negative on error
 */
int wendy_hal_gpio_read(int pin);

/**
 * Write a GPIO output level.
 * @param pin    GPIO number
 * @param level  0 = low, 1 = high
 * @return 0 on success
 */
int wendy_hal_gpio_write(int pin, int level);

/**
 * Set PWM output on a GPIO pin.
 * @param pin       GPIO number
 * @param freq_hz   PWM frequency in Hz
 * @param duty_pct  Duty cycle 0–100
 * @return 0 on success
 */
int wendy_hal_gpio_set_pwm(int pin, uint32_t freq_hz, uint8_t duty_pct);

/* ── I2C ────────────────────────────────────────────────────────────── */

/**
 * Initialize an I2C bus.
 * @param bus       I2C port number (0 or 1)
 * @param sda_pin   SDA GPIO
 * @param scl_pin   SCL GPIO
 * @param freq_hz   Clock frequency
 * @return 0 on success
 */
int wendy_hal_i2c_init(int bus, int sda_pin, int scl_pin, uint32_t freq_hz);

/**
 * Scan the I2C bus for devices.
 * @param bus          I2C port number
 * @param addrs_out    Buffer to receive found addresses
 * @param max_addrs    Size of addrs_out
 * @return Number of devices found, or negative on error
 */
int wendy_hal_i2c_scan(int bus, uint8_t *addrs_out, int max_addrs);

/**
 * Write bytes to an I2C device.
 * @param bus      I2C port number
 * @param addr     7-bit device address
 * @param data     Data to write
 * @param len      Number of bytes
 * @return 0 on success
 */
int wendy_hal_i2c_write(int bus, uint8_t addr, const uint8_t *data, int len);

/**
 * Read bytes from an I2C device.
 * @param bus      I2C port number
 * @param addr     7-bit device address
 * @param buf      Buffer for received data
 * @param len      Number of bytes to read
 * @return 0 on success
 */
int wendy_hal_i2c_read(int bus, uint8_t addr, uint8_t *buf, int len);

/**
 * Combined write-then-read I2C transaction (e.g., register read).
 * @param bus          I2C port
 * @param addr         7-bit device address
 * @param write_data   Data to write (register address, etc.)
 * @param write_len    Bytes to write
 * @param read_buf     Buffer for response
 * @param read_len     Bytes to read
 * @return 0 on success
 */
int wendy_hal_i2c_write_read(int bus, uint8_t addr,
                              const uint8_t *write_data, int write_len,
                              uint8_t *read_buf, int read_len);

/* ── Timer ──────────────────────────────────────────────────────────── */

/**
 * Blocking delay.
 * @param ms  Milliseconds to sleep
 */
void wendy_hal_timer_delay_ms(uint32_t ms);

/**
 * Get monotonic time in milliseconds since boot.
 */
uint64_t wendy_hal_timer_millis(void);

/**
 * Schedule a one-shot callback after `ms` milliseconds.
 * @param ms   Delay in milliseconds
 * @param cb   Callback function
 * @param arg  Argument passed to callback
 * @return Timer ID (>0) on success, negative on error
 */
int wendy_hal_timer_schedule(uint32_t ms, void (*cb)(void *), void *arg);

/**
 * Cancel a scheduled timer.
 * @param timer_id  ID returned by wendy_hal_timer_schedule
 * @return 0 on success
 */
int wendy_hal_timer_cancel(int timer_id);

#ifdef __cplusplus
}
#endif
