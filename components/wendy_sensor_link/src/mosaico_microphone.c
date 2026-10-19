#include "mic.h"

#include <stdbool.h>
#include <limits.h>

#include "bsp/esp_mosaico.h"
#include "esp_codec_dev.h"

static esp_codec_dev_handle_t s_microphone;
static bool s_started;

esp_err_t mic_init(void)
{
    if (!s_microphone) {
        // Reserve mono DMA buffers at the actual capture format. The BSP's
        // default stereo buffers waste internal RAM and are reallocated when
        // the first subscriber opens the mono codec.
        i2s_std_config_t config = {
            .clk_cfg = I2S_STD_CLK_DEFAULT_CONFIG(MIC_SAMPLE_RATE_HZ),
            .slot_cfg = I2S_STD_PHILIPS_SLOT_DEFAULT_CONFIG(I2S_DATA_BIT_WIDTH_16BIT, I2S_SLOT_MODE_MONO),
            .gpio_cfg = {
                .mclk = BSP_AUDIO_I2S_MCLK,
                .bclk = BSP_AUDIO_I2S_SCLK,
                .ws = BSP_AUDIO_I2S_LRCLK,
                .dout = BSP_AUDIO_I2S_SDOUT,
                .din = BSP_AUDIO_I2S_DSIN,
            },
        };
        esp_err_t err = bsp_audio_init(&config);
        if (err != ESP_OK) {
            return err;
        }
        // The BSP owns the shared I2S bus and caches this codec handle.
        s_microphone = bsp_audio_codec_microphone_init();
    }
    return s_microphone ? ESP_OK : ESP_FAIL;
}

esp_err_t mic_start(void)
{
    if (!s_microphone) {
        return ESP_ERR_INVALID_STATE;
    }
    if (s_started) {
        return ESP_OK;
    }
    esp_codec_dev_sample_info_t format = {
        .sample_rate = MIC_SAMPLE_RATE_HZ,
        .bits_per_sample = 16,
        .channel = MIC_CHANNELS,
        .channel_mask = 0,
    };
    if (esp_codec_dev_open(s_microphone, &format) != ESP_CODEC_DEV_OK) {
        return ESP_FAIL;
    }
    if (esp_codec_dev_set_in_gain(s_microphone, 30.0f) != ESP_CODEC_DEV_OK) {
        esp_codec_dev_close(s_microphone);
        return ESP_FAIL;
    }
    s_started = true;
    return ESP_OK;
}

esp_err_t mic_read(int16_t *buffer, size_t samples, size_t *bytes_read)
{
    if (!buffer || !bytes_read || samples == 0 || samples > INT_MAX / sizeof(*buffer)) {
        return ESP_ERR_INVALID_ARG;
    }
    *bytes_read = 0;
    if (!s_started) {
        return ESP_ERR_INVALID_STATE;
    }
    size_t size = samples * sizeof(*buffer);
    if (esp_codec_dev_read(s_microphone, buffer, (int)size) != ESP_CODEC_DEV_OK) {
        return ESP_FAIL;
    }
    *bytes_read = size;
    return ESP_OK;
}

void mic_stop(void)
{
    if (s_started) {
        esp_codec_dev_close(s_microphone);
        s_started = false;
    }
}

void mic_deinit(void)
{
    mic_stop();
    // Do not delete the BSP's cached codec or shared I2S resources.
}
