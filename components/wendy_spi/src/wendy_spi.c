#include "wendy_spi.h"

#include <string.h>
#include "driver/spi_master.h"
#include "soc/soc_caps.h"
#include "esp_log.h"
#include "wasm_export.h"
#include "wendy_safety.h"

static const char *TAG = "wendy_spi";

#define MAX_SPI_DEVS 4

typedef struct {
    bool opened;
    spi_device_handle_t handle;
    spi_host_device_t host;
} spi_dev_t;

static spi_dev_t s_spi_devs[MAX_SPI_DEVS];
static bool s_bus_initialized[SOC_SPI_PERIPH_NUM];

/*
 * spi_open(host, mosi, miso, sclk, cs, clock_hz) -> dev_id (>=0) or -1
 */
static int spi_open_wrapper(wasm_exec_env_t exec_env,
                             int host, int mosi, int miso,
                             int sclk, int cs, int clock_hz)
{
    if (host < 1 || host > (SOC_SPI_PERIPH_NUM - 1)) {
        ESP_LOGE(TAG, "invalid SPI host %d (max %d)", host, SOC_SPI_PERIPH_NUM - 1);
        return -1;
    }

    /* Find free device slot */
    int dev_id = -1;
    for (int i = 0; i < MAX_SPI_DEVS; i++) {
        if (!s_spi_devs[i].opened) {
            dev_id = i;
            break;
        }
    }
    if (dev_id < 0) {
        ESP_LOGE(TAG, "no free SPI device slots");
        return -1;
    }

    /* host=1 maps to SPI2_HOST, host=2 maps to SPI3_HOST (if available) */
    spi_host_device_t spi_host = (spi_host_device_t)(SPI2_HOST + (host - 1));

    /* Initialize bus if not already done */
    if (!s_bus_initialized[host]) {
        spi_bus_config_t bus_cfg = {
            .mosi_io_num = mosi,
            .miso_io_num = miso,
            .sclk_io_num = sclk,
            .quadwp_io_num = -1,
            .quadhd_io_num = -1,
            .max_transfer_sz = 4096,
        };
        esp_err_t err = spi_bus_initialize(spi_host, &bus_cfg, SPI_DMA_CH_AUTO);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "spi_bus_initialize failed: %s", esp_err_to_name(err));
            return -1;
        }
        s_bus_initialized[host] = true;
    }

    spi_device_interface_config_t dev_cfg = {
        .clock_speed_hz = clock_hz,
        .mode = 0,
        .spics_io_num = cs,
        .queue_size = 1,
    };

    esp_err_t err = spi_bus_add_device(spi_host, &dev_cfg, &s_spi_devs[dev_id].handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "spi_bus_add_device failed: %s", esp_err_to_name(err));
        return -1;
    }

    s_spi_devs[dev_id].opened = true;
    s_spi_devs[dev_id].host = spi_host;
    ESP_LOGI(TAG, "SPI dev %d opened (host=%d cs=%d clk=%d)", dev_id, host, cs, clock_hz);
    return dev_id;
}

/* spi_close(dev_id) -> 0 ok */
static int spi_close_wrapper(wasm_exec_env_t exec_env, int dev_id)
{
    if (dev_id < 0 || dev_id >= MAX_SPI_DEVS || !s_spi_devs[dev_id].opened) {
        return -1;
    }
    spi_bus_remove_device(s_spi_devs[dev_id].handle);
    s_spi_devs[dev_id].opened = false;
    return 0;
}

/*
 * spi_transfer(dev_id, tx_offset, rx_offset, len) -> 0 ok
 * tx_offset/rx_offset are WASM pointers; either can be 0 for write-only or read-only.
 */
static int spi_transfer_wrapper(wasm_exec_env_t exec_env,
                                 int dev_id, uint32_t tx_offset,
                                 uint32_t rx_offset, int len)
{
    if (dev_id < 0 || dev_id >= MAX_SPI_DEVS || !s_spi_devs[dev_id].opened) {
        return -1;
    }
    if (len <= 0 || len > 4096) {
        return -1;
    }

    uint8_t *tx_buf = NULL;
    uint8_t *rx_buf = NULL;

    if (tx_offset) {
        tx_buf = wendy_safety_get_native_ptr(exec_env, tx_offset, len);
        if (!tx_buf) return -1;
    }
    if (rx_offset) {
        rx_buf = wendy_safety_get_native_ptr(exec_env, rx_offset, len);
        if (!rx_buf) return -1;
    }

    spi_transaction_t trans = {
        .length = len * 8,
        .tx_buffer = tx_buf,
        .rx_buffer = rx_buf,
    };

    esp_err_t err = spi_device_transmit(s_spi_devs[dev_id].handle, &trans);
    return (err == ESP_OK) ? 0 : -1;
}

static NativeSymbol s_spi_symbols[] = {
    { "spi_open",     (void *)spi_open_wrapper,     "(iiiiii)i", NULL },
    { "spi_close",    (void *)spi_close_wrapper,    "(i)i",      NULL },
    { "spi_transfer", (void *)spi_transfer_wrapper, "(iiii)i",   NULL },
};

int wendy_spi_export_init(void)
{
    memset(s_spi_devs, 0, sizeof(s_spi_devs));
    memset(s_bus_initialized, 0, sizeof(s_bus_initialized));

    if (!wasm_runtime_register_natives("wendy",
                                       s_spi_symbols,
                                       sizeof(s_spi_symbols) / sizeof(s_spi_symbols[0]))) {
        ESP_LOGE(TAG, "failed to register SPI natives");
        return -1;
    }
    ESP_LOGI(TAG, "SPI exports registered");
    return 0;
}
