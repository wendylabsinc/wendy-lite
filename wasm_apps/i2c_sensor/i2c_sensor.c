/**
 * Wendy MCU — Example WASM Application: I2C Sensor Reader
 *
 * Reads temperature from a BME280/BMP280 sensor on I2C bus 0.
 *
 * Build with:
 *   clang --target=wasm32 -O2 -nostdlib \
 *     -I ../include \
 *     -Wl,--no-entry -Wl,--export=_start \
 *     -Wl,--allow-undefined \
 *     -o i2c_sensor.wasm i2c_sensor.c
 */

#include "wendy.h"

/* ── Helpers ────────────────────────────────────────────────────────── */

static int str_len(const char *s)
{
    int n = 0;
    while (s[n]) n++;
    return n;
}

static void print(const char *msg)
{
    wendy_print(msg, str_len(msg));
}

/* Simple integer-to-string for printing */
static void print_int(int val)
{
    char buf[12];
    int neg = 0;
    if (val < 0) { neg = 1; val = -val; }
    int i = sizeof(buf) - 1;
    buf[i] = 0;
    do {
        buf[--i] = '0' + (val % 10);
        val /= 10;
    } while (val > 0);
    if (neg) buf[--i] = '-';
    wendy_print(buf + i, str_len(buf + i));
}

/* ── BMP280 registers ───────────────────────────────────────────────── */

#define BMP280_ADDR     0x76
#define BMP280_REG_ID   0xD0
#define BMP280_REG_CTRL 0xF4
#define BMP280_REG_TEMP 0xFA

void _start(void)
{
    print("Wendy I2C Sensor App starting\n");

    /* Scan for devices */
    unsigned char addrs[16];
    int found = i2c_scan(0, addrs, 16);
    print("I2C scan found ");
    print_int(found);
    print(" device(s)\n");

    for (int i = 0; i < found; i++) {
        print("  - 0x");
        char hex[3];
        hex[0] = "0123456789ABCDEF"[addrs[i] >> 4];
        hex[1] = "0123456789ABCDEF"[addrs[i] & 0xF];
        hex[2] = 0;
        print(hex);
        print("\n");
    }

    /* Read chip ID */
    unsigned char reg = BMP280_REG_ID;
    unsigned char chip_id = 0;
    if (i2c_write_read(0, BMP280_ADDR, &reg, 1, &chip_id, 1) != 0) {
        print("ERROR: failed to read chip ID\n");
        return;
    }

    print("BMP280 chip ID: 0x");
    char hex[3];
    hex[0] = "0123456789ABCDEF"[chip_id >> 4];
    hex[1] = "0123456789ABCDEF"[chip_id & 0xF];
    hex[2] = 0;
    print(hex);
    print("\n");

    /* Configure: normal mode, temp oversampling x1 */
    unsigned char ctrl_cmd[2] = { BMP280_REG_CTRL, 0x27 };
    i2c_write(0, BMP280_ADDR, ctrl_cmd, 2);
    timer_delay_ms(100);

    /* Read temperature 10 times */
    for (int i = 0; i < 10; i++) {
        unsigned char temp_reg = BMP280_REG_TEMP;
        unsigned char raw[3];
        if (i2c_write_read(0, BMP280_ADDR, &temp_reg, 1, raw, 3) != 0) {
            print("ERROR: temp read failed\n");
            break;
        }

        int raw_temp = ((int)raw[0] << 12) | ((int)raw[1] << 4) | (raw[2] >> 4);
        /* Simplified conversion (actual BMP280 needs calibration data) */
        int temp_approx = raw_temp / 500;

        print("Temperature reading #");
        print_int(i + 1);
        print(": raw=");
        print_int(raw_temp);
        print(" (~");
        print_int(temp_approx / 10);
        print(".");
        print_int(temp_approx % 10);
        print(" C)\n");

        timer_delay_ms(1000);
    }

    print("Sensor reading complete.\n");
}
