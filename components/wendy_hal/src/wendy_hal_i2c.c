#include "wendy_hal.h"

#include "driver/i2c_master.h"
#include "esp_log.h"

static const char *TAG = "wendy_hal_i2c";

#define I2C_TIMEOUT_MS  1000
#define MAX_I2C_BUSES   2

static i2c_master_bus_handle_t s_bus_handles[MAX_I2C_BUSES] = { NULL, NULL };
static uint32_t s_bus_freq_hz[MAX_I2C_BUSES] = { 100000, 100000 };

int wendy_hal_i2c_init(int bus, int sda_pin, int scl_pin, uint32_t freq_hz)
{
    if (bus < 0 || bus >= MAX_I2C_BUSES) {
        return -1;
    }
    if (s_bus_handles[bus]) {
        ESP_LOGW(TAG, "I2C bus %d already initialized", bus);
        return 0;
    }

    s_bus_freq_hz[bus] = freq_hz;

    i2c_master_bus_config_t bus_cfg = {
        .i2c_port   = (i2c_port_num_t)bus,
        .sda_io_num = (gpio_num_t)sda_pin,
        .scl_io_num = (gpio_num_t)scl_pin,
        .clk_source = I2C_CLK_SRC_DEFAULT,
        .glitch_ignore_cnt = 7,
        .flags.enable_internal_pullup = true,
    };

    esp_err_t err = i2c_new_master_bus(&bus_cfg, &s_bus_handles[bus]);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "i2c_new_master_bus(%d) failed: %s", bus, esp_err_to_name(err));
        return -1;
    }

    ESP_LOGI(TAG, "I2C bus %d initialized (SDA=%d SCL=%d %luHz)",
             bus, sda_pin, scl_pin, (unsigned long)freq_hz);
    return 0;
}

/* Helper: create a temporary device handle for a transaction */
static i2c_master_dev_handle_t i2c_get_dev(int bus, uint8_t addr)
{
    if (bus < 0 || bus >= MAX_I2C_BUSES || !s_bus_handles[bus]) {
        return NULL;
    }

    i2c_device_config_t dev_cfg = {
        .dev_addr_length = I2C_ADDR_BIT_LEN_7,
        .device_address  = addr,
        .scl_speed_hz    = s_bus_freq_hz[bus],
    };

    i2c_master_dev_handle_t dev = NULL;
    if (i2c_master_bus_add_device(s_bus_handles[bus], &dev_cfg, &dev) != ESP_OK) {
        return NULL;
    }
    return dev;
}

int wendy_hal_i2c_scan(int bus, uint8_t *addrs_out, int max_addrs)
{
    if (bus < 0 || bus >= MAX_I2C_BUSES || !s_bus_handles[bus]) {
        return -1;
    }

    int found = 0;
    for (uint8_t addr = 0x08; addr < 0x78 && found < max_addrs; addr++) {
        esp_err_t err = i2c_master_probe(s_bus_handles[bus], addr, I2C_TIMEOUT_MS);
        if (err == ESP_OK) {
            if (addrs_out) {
                addrs_out[found] = addr;
            }
            found++;
        }
    }
    return found;
}

int wendy_hal_i2c_write(int bus, uint8_t addr, const uint8_t *data, int len)
{
    i2c_master_dev_handle_t dev = i2c_get_dev(bus, addr);
    if (!dev) return -1;

    esp_err_t err = i2c_master_transmit(dev, data, len, I2C_TIMEOUT_MS);
    i2c_master_bus_rm_device(dev);
    return (err == ESP_OK) ? 0 : -1;
}

int wendy_hal_i2c_read(int bus, uint8_t addr, uint8_t *buf, int len)
{
    i2c_master_dev_handle_t dev = i2c_get_dev(bus, addr);
    if (!dev) return -1;

    esp_err_t err = i2c_master_receive(dev, buf, len, I2C_TIMEOUT_MS);
    i2c_master_bus_rm_device(dev);
    return (err == ESP_OK) ? 0 : -1;
}

int wendy_hal_i2c_write_read(int bus, uint8_t addr,
                              const uint8_t *write_data, int write_len,
                              uint8_t *read_buf, int read_len)
{
    i2c_master_dev_handle_t dev = i2c_get_dev(bus, addr);
    if (!dev) return -1;

    esp_err_t err = i2c_master_transmit_receive(dev,
                                                 write_data, write_len,
                                                 read_buf, read_len,
                                                 I2C_TIMEOUT_MS);
    i2c_master_bus_rm_device(dev);
    return (err == ESP_OK) ? 0 : -1;
}
