#include "mic.h"

#include "freertos/FreeRTOS.h"

#include "driver/i2s_pdm.h"
#include "esp_log.h"

static const char *TAG = "mic";

// Onboard PDM MEMS microphone on the XIAO ESP32S3 Sense expansion board.
// PDM RX is only supported on I2S_NUM_0 on the S3.
#define MIC_PIN_CLK GPIO_NUM_42
#define MIC_PIN_DIN GPIO_NUM_41

static i2s_chan_handle_t s_rx_handle;

esp_err_t mic_init(void)
{
    if (s_rx_handle) {
        return ESP_OK;
    }

    i2s_chan_config_t chan_cfg = I2S_CHANNEL_DEFAULT_CONFIG(I2S_NUM_0, I2S_ROLE_MASTER);
    // Eight 20 ms buffers, one per block a frame can carry. The driver queues
    // up to seven filled ones, so about 140 ms of audio survives a slow send;
    // the default queued 75 ms.
    chan_cfg.dma_frame_num = MIC_READ_SAMPLES;
    chan_cfg.dma_desc_num = MIC_MAX_READ_SAMPLES / MIC_READ_SAMPLES;
    esp_err_t err = i2s_new_channel(&chan_cfg, NULL, &s_rx_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "i2s_new_channel failed: %s", esp_err_to_name(err));
        return err;
    }

    i2s_pdm_rx_config_t pdm_rx_cfg = {
        .clk_cfg = I2S_PDM_RX_CLK_DEFAULT_CONFIG(MIC_SAMPLE_RATE_HZ),
        .slot_cfg = I2S_PDM_RX_SLOT_DEFAULT_CONFIG(I2S_DATA_BIT_WIDTH_16BIT, I2S_SLOT_MODE_MONO),
        .gpio_cfg = {
            .clk = MIC_PIN_CLK,
            .din = MIC_PIN_DIN,
            .invert_flags = {
                .clk_inv = false,
            },
        },
    };
    err = i2s_channel_init_pdm_rx_mode(s_rx_handle, &pdm_rx_cfg);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "i2s_channel_init_pdm_rx_mode failed: %s", esp_err_to_name(err));
        i2s_del_channel(s_rx_handle);
        s_rx_handle = NULL;
        return err;
    }

    return ESP_OK;
}

void mic_deinit(void)
{
    if (s_rx_handle) {
        i2s_del_channel(s_rx_handle);
        s_rx_handle = NULL;
    }
}

esp_err_t mic_start(void)
{
    if (!s_rx_handle) {
        return ESP_ERR_INVALID_STATE;
    }
    return i2s_channel_enable(s_rx_handle);
}

esp_err_t mic_read(int16_t *buffer, size_t samples, size_t *bytes_read)
{
    if (!s_rx_handle) {
        return ESP_ERR_INVALID_STATE;
    }
    return i2s_channel_read(s_rx_handle, buffer, samples * sizeof(*buffer), bytes_read, 100);
}

esp_err_t mic_read_queued(int16_t *buffer, size_t samples, size_t *bytes_read)
{
    if (!s_rx_handle) {
        return ESP_ERR_INVALID_STATE;
    }
    // A zero timeout copies the DMA buffers already filled, then reports a
    // timeout at the first one still being written.
    esp_err_t err = i2s_channel_read(s_rx_handle, buffer, samples * sizeof(*buffer), bytes_read, 0);
    return err == ESP_ERR_TIMEOUT ? ESP_OK : err;
}

void mic_stop(void)
{
    if (s_rx_handle) {
        i2s_channel_disable(s_rx_handle);
    }
}
