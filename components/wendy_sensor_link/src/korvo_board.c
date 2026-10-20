#include "korvo_board.h"

static i2c_master_bus_handle_t s_bus;
static unsigned s_users;

esp_err_t korvo_i2c_acquire(i2c_master_bus_handle_t *bus)
{
    if (!s_bus) {
        const i2c_master_bus_config_t config = {
            .i2c_port = I2C_NUM_0,
            .sda_io_num = GPIO_NUM_0,
            .scl_io_num = GPIO_NUM_1,
            .clk_source = I2C_CLK_SRC_DEFAULT,
            .glitch_ignore_cnt = 7,
            .flags.enable_internal_pullup = true,
        };
        esp_err_t err = i2c_new_master_bus(&config, &s_bus);
        if (err != ESP_OK) {
            return err;
        }
    }
    ++s_users;
    *bus = s_bus;
    return ESP_OK;
}

void korvo_i2c_release(void)
{
    if (s_users && --s_users == 0) {
        i2c_del_master_bus(s_bus);
        s_bus = NULL;
    }
}
