#include "wendy_hal.h"
#include "esp_log.h"
#include "driver/rmt_tx.h"
#include "driver/rmt_encoder.h"

static const char *TAG = "wendy_hal_rmt";

#define RMT_MAX_CHANNELS 4

typedef struct {
    bool in_use;
    int pin;
    rmt_channel_handle_t channel;
    rmt_encoder_handle_t encoder;
} rmt_slot_t;

static rmt_slot_t s_slots[RMT_MAX_CHANNELS];

static int find_free_slot(void)
{
    for (int i = 0; i < RMT_MAX_CHANNELS; i++) {
        if (!s_slots[i].in_use) return i;
    }
    return -1;
}

int wendy_hal_rmt_configure(int pin, int resolution_hz)
{
    int slot = find_free_slot();
    if (slot < 0) {
        ESP_LOGE(TAG, "no free RMT channel slots");
        return -1;
    }

    rmt_tx_channel_config_t tx_cfg = {
        .gpio_num = pin,
        .clk_src = RMT_CLK_SRC_DEFAULT,
        .resolution_hz = (uint32_t)resolution_hz,
        .mem_block_symbols = 64,
        .trans_queue_depth = 1,
    };

    esp_err_t err = rmt_new_tx_channel(&tx_cfg, &s_slots[slot].channel);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "rmt_new_tx_channel failed: %s", esp_err_to_name(err));
        return -1;
    }

    rmt_copy_encoder_config_t enc_cfg = {};
    err = rmt_new_copy_encoder(&enc_cfg, &s_slots[slot].encoder);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "rmt_new_copy_encoder failed: %s", esp_err_to_name(err));
        rmt_del_channel(s_slots[slot].channel);
        return -1;
    }

    err = rmt_enable(s_slots[slot].channel);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "rmt_enable failed: %s", esp_err_to_name(err));
        rmt_del_encoder(s_slots[slot].encoder);
        rmt_del_channel(s_slots[slot].channel);
        return -1;
    }

    s_slots[slot].in_use = true;
    s_slots[slot].pin = pin;

    ESP_LOGI(TAG, "RMT channel %d configured: pin=%d, res=%d Hz", slot, pin, resolution_hz);
    return slot;
}

int wendy_hal_rmt_transmit(int channel_id, const unsigned char *buf, int len)
{
    if (channel_id < 0 || channel_id >= RMT_MAX_CHANNELS || !s_slots[channel_id].in_use) {
        return -1;
    }

    if (!buf || len <= 0 || (len % 4) != 0) {
        ESP_LOGE(TAG, "invalid buffer: len=%d (must be >0 and multiple of 4)", len);
        return -1;
    }

    rmt_transmit_config_t tx_config = {
        .loop_count = 0,
    };

    rmt_slot_t *slot = &s_slots[channel_id];
    esp_err_t err = rmt_transmit(slot->channel, slot->encoder,
                                  buf, (size_t)len, &tx_config);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "rmt_transmit failed: %s", esp_err_to_name(err));
        return -1;
    }

    err = rmt_tx_wait_all_done(slot->channel, 1000);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "rmt_tx_wait_all_done failed: %s", esp_err_to_name(err));
        return -1;
    }

    return 0;
}

int wendy_hal_rmt_release(int channel_id)
{
    if (channel_id < 0 || channel_id >= RMT_MAX_CHANNELS || !s_slots[channel_id].in_use) {
        return -1;
    }

    rmt_slot_t *slot = &s_slots[channel_id];

    rmt_disable(slot->channel);
    rmt_del_encoder(slot->encoder);
    rmt_del_channel(slot->channel);

    slot->in_use = false;
    slot->channel = NULL;
    slot->encoder = NULL;
    slot->pin = -1;

    ESP_LOGI(TAG, "RMT channel %d released", channel_id);
    return 0;
}

void wendy_hal_rmt_release_all(void)
{
    for (int i = 0; i < RMT_MAX_CHANNELS; i++) {
        if (s_slots[i].in_use) {
            wendy_hal_rmt_release(i);
        }
    }
}
