/**
 * wendy.h — C header for WASM applications targeting Wendy MCU.
 *
 * This header declares all host-imported functions from the "wendy"
 * module. Include this in your WASM app source files.
 *
 * Build your app with:
 *   clang --target=wasm32 -O2 -nostdlib \
 *     -I path/to/wasm_apps/include \
 *     -Wl,--no-entry -Wl,--export=_start \
 *     -Wl,--allow-undefined \
 *     -o app.wasm app.c
 */

#pragma once

/* ── GPIO ───────────────────────────────────────────────────────────── */

#define WENDY_GPIO_INPUT        0
#define WENDY_GPIO_OUTPUT       1
#define WENDY_GPIO_INPUT_OUTPUT 2

#define WENDY_GPIO_PULL_NONE    0
#define WENDY_GPIO_PULL_UP      1
#define WENDY_GPIO_PULL_DOWN    2

__attribute__((import_module("wendy"), import_name("gpio_configure")))
int gpio_configure(int pin, int mode, int pull);

__attribute__((import_module("wendy"), import_name("gpio_read")))
int gpio_read(int pin);

__attribute__((import_module("wendy"), import_name("gpio_write")))
int gpio_write(int pin, int level);

__attribute__((import_module("wendy"), import_name("gpio_set_pwm")))
int gpio_set_pwm(int pin, int freq_hz, int duty_pct);

/* ── I2C ────────────────────────────────────────────────────────────── */

__attribute__((import_module("wendy"), import_name("i2c_init")))
int i2c_init(int bus, int sda, int scl, int freq_hz);

__attribute__((import_module("wendy"), import_name("i2c_scan")))
int i2c_scan(int bus, unsigned char *addrs_out, int max_addrs);

__attribute__((import_module("wendy"), import_name("i2c_write")))
int i2c_write(int bus, int addr, const unsigned char *data, int len);

__attribute__((import_module("wendy"), import_name("i2c_read")))
int i2c_read(int bus, int addr, unsigned char *buf, int len);

__attribute__((import_module("wendy"), import_name("i2c_write_read")))
int i2c_write_read(int bus, int addr,
                    const unsigned char *wr, int wr_len,
                    unsigned char *rd, int rd_len);

/* ── Timer ──────────────────────────────────────────────────────────── */

__attribute__((import_module("wendy"), import_name("timer_delay_ms")))
void timer_delay_ms(int ms);

__attribute__((import_module("wendy"), import_name("timer_millis")))
long long timer_millis(void);

/* ── Console output ─────────────────────────────────────────────────── */

__attribute__((import_module("wendy"), import_name("wendy_print")))
int wendy_print(const char *buf, int len);
