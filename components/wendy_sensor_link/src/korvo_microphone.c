#include "mic.h"

#include <limits.h>
#include <stdbool.h>

#include "driver/i2s_tdm.h"
#include "esp_codec_dev.h"
#include "esp_codec_dev_defaults.h"
#include "esp_log.h"
#include "korvo_board.h"

static const char *TAG = "korvo_mic";
static i2s_chan_handle_t s_rx;
static const audio_codec_ctrl_if_t *s_control;
static const audio_codec_data_if_t *s_data;
static const audio_codec_if_t *s_codec;
static esp_codec_dev_handle_t s_device;
static bool s_i2c_acquired;
static bool s_started;

void mic_stop(void)
{
    if (s_started) {
        esp_codec_dev_close(s_device);
        s_started = false;
    }
}

void mic_deinit(void)
{
    mic_stop();
    if (s_device) {
        esp_codec_dev_delete(s_device);
        s_device = NULL;
    }
    if (s_codec) {
        audio_codec_delete_codec_if(s_codec);
        s_codec = NULL;
    }
    if (s_data) {
        audio_codec_delete_data_if(s_data);
        s_data = NULL;
    }
    if (s_control) {
        audio_codec_delete_ctrl_if(s_control);
        s_control = NULL;
    }
    if (s_rx) {
        i2s_del_channel(s_rx);
        s_rx = NULL;
    }
    if (s_i2c_acquired) {
        korvo_i2c_release();
        s_i2c_acquired = false;
    }
}

esp_err_t mic_init(void)
{
    if (s_device) {
        return ESP_OK;
    }
    i2c_master_bus_handle_t bus;
    esp_err_t err = korvo_i2c_acquire(&bus);
    if (err != ESP_OK) {
        return err;
    }
    s_i2c_acquired = true;

    i2s_chan_config_t channel = I2S_CHANNEL_DEFAULT_CONFIG(I2S_NUM_0, I2S_ROLE_MASTER);
    channel.dma_desc_num = 6;
    channel.dma_frame_num = 320;
    err = i2s_new_channel(&channel, NULL, &s_rx);
    if (err != ESP_OK) {
        goto fail;
    }
    i2s_tdm_config_t tdm = {
        .clk_cfg = I2S_TDM_CLK_DEFAULT_CONFIG(MIC_SAMPLE_RATE_HZ),
        .slot_cfg = I2S_TDM_PHILIPS_SLOT_DEFAULT_CONFIG(I2S_DATA_BIT_WIDTH_16BIT,
                                                      I2S_SLOT_MODE_STEREO,
                                                      I2S_TDM_SLOT0 | I2S_TDM_SLOT1),
        .gpio_cfg = {
            .mclk = GPIO_NUM_NC,
            .bclk = GPIO_NUM_3,
            .ws = GPIO_NUM_4,
            .dout = GPIO_NUM_NC,
            .din = GPIO_NUM_6,
        },
    };
    tdm.clk_cfg.clk_src = I2S_CLK_SRC_XTAL;
    tdm.slot_cfg.total_slot = 2;
    tdm.slot_cfg.ws_width = 16;
    err = i2s_channel_init_tdm_mode(s_rx, &tdm);
    if (err != ESP_OK) {
        goto fail;
    }
    audio_codec_i2s_cfg_t data = {
        .port = I2S_NUM_0,
        .rx_handle = s_rx,
        .clk_src = I2S_CLK_SRC_XTAL,
    };
    s_data = audio_codec_new_i2s_data(&data);
    // Espressif's S31 ES8389 tests use 10 kHz for reliable codec access.
    // Camera SCCB uses its own per-device rate on the same I2C bus.
    audio_codec_i2c_cfg_t control = {
        .addr = ES8389_CODEC_DEFAULT_ADDR,
        .bus_handle = bus,
        .clock_speed_hz = 10000,
    };
    s_control = audio_codec_new_i2c_ctrl(&control);
    if (!s_data || !s_control) {
        err = ESP_ERR_NO_MEM;
        goto fail;
    }
    es8389_codec_cfg_t codec = {
        .ctrl_if = s_control,
        .sys_cfg.no_mclk = true,
        .adc_cfg.label = "FL,FR",
        .dac_cfg.ref_enable = false,
        .pa_cfg.pa_pin = -1,
    };
    s_codec = es8389_codec_new(&codec);
    if (!s_codec) {
        err = ESP_ERR_NOT_FOUND;
        goto fail;
    }
    esp_codec_dev_cfg_t device = {
        .dev_type = ESP_CODEC_DEV_TYPE_IN,
        .codec_if = s_codec,
        .data_if = s_data,
    };
    s_device = esp_codec_dev_new(&device);
    if (!s_device) {
        err = ESP_ERR_NO_MEM;
        goto fail;
    }
    if (esp_codec_dev_set_in_gain(s_device, 24.0f) != ESP_CODEC_DEV_OK) {
        err = ESP_FAIL;
        goto fail;
    }
    ESP_LOGI(TAG, "ES8389 ready: %d Hz stereo PCM", MIC_SAMPLE_RATE_HZ);
    return ESP_OK;
fail:
    mic_deinit();
    return err;
}

esp_err_t mic_start(void)
{
    if (!s_device) {
        return ESP_ERR_INVALID_STATE;
    }
    if (s_started) {
        return ESP_OK;
    }
    esp_codec_dev_sample_info_t format = {
        .sample_rate = MIC_SAMPLE_RATE_HZ,
        .channel = MIC_CHANNELS,
        .channel_mask = 0x03,
        .bits_per_sample = 16,
        .mclk_multiple = 256,
    };
    if (esp_codec_dev_open(s_device, &format) != ESP_CODEC_DEV_OK) {
        esp_codec_dev_close(s_device);
        return ESP_FAIL;
    }
    // Request left/right explicitly; the codec can map TDM bus slot order.
    if (esp_codec_dev_set_data_layout_label(s_device, "FL,FR") != ESP_CODEC_DEV_OK) {
        esp_codec_dev_close(s_device);
        return ESP_FAIL;
    }
    s_started = true;
    return ESP_OK;
}

esp_err_t mic_read(int16_t *buffer, size_t samples, size_t *bytes_read)
{
    if (!buffer || !bytes_read || !samples || samples % MIC_CHANNELS || samples > INT_MAX / sizeof(*buffer)) {
        return ESP_ERR_INVALID_ARG;
    }
    *bytes_read = 0;
    if (!s_started) {
        return ESP_ERR_INVALID_STATE;
    }
    int size = samples * sizeof(*buffer);
    if (esp_codec_dev_read(s_device, buffer, size) != ESP_CODEC_DEV_OK) {
        return ESP_FAIL;
    }
    *bytes_read = size;
    return ESP_OK;
}
