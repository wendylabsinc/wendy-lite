#include "wendy_ble_setup.h"
#include "wendy_ble_setup_crypto.h"
#include "wendy_ble_setup_wire.h"
#include "wendy_ble_l2cap.h"
#include "wendy_com_link.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "mbedtls/platform_util.h"
#include "pb_encode.h"
#include <stdlib.h>
#include <string.h>

/* A deadline covers the whole frame, so partial writes/slow peers cannot keep
 * an unfinished handshake or frame alive indefinitely. */
static bool transfer(void *data, size_t size, bool writing, int64_t deadline)
{
    uint8_t *p = data;
    while (size && wble_l2cap_session_alive() && esp_timer_get_time() < deadline) {
        ssize_t n = writing ? wble_l2cap_write(p, size) : wble_l2cap_read(p, size);
        if (n > 0) {
            if ((size_t)n > size) return false;
            p += n; size -= n;
        } else if (n == WBLE_ERR_WANT_READ || n == WBLE_ERR_WANT_WRITE) {
            if (n == WBLE_ERR_WANT_READ) wble_l2cap_wait_readable(pdMS_TO_TICKS(100));
            else wble_l2cap_wait_writable(pdMS_TO_TICKS(100));
        } else return false;
    }
    return size == 0;
}

static uint8_t *read_frame(size_t limit, size_t *size, int64_t deadline)
{
    uint8_t length[2];
    *size = 0;
    if (!transfer(length, 2, false, deadline)) return NULL;
    size_t n = (size_t)length[0] * 256 + length[1];
    if (!n || n > limit) return NULL;
    uint8_t *data = malloc(n);
    if (!data) return NULL;
    if (!transfer(data, n, false, deadline)) {
        mbedtls_platform_zeroize(data, n);
        free(data);
        return NULL;
    }
    *size = n;
    return data;
}

static bool write_bytes_message(uint32_t outer, uint8_t *data, size_t size, int64_t deadline)
{
    uint8_t header[16];
    pb_ostream_t measure = PB_OSTREAM_SIZING;
    if (!pb_encode_tag(&measure, PB_WT_STRING, 1) || !pb_encode_varint(&measure, size)) return false;
    size_t inner_header_size = measure.bytes_written;
    pb_ostream_t output = pb_ostream_from_buffer(header + 2, sizeof header - 2);
    if (!pb_encode_tag(&output, PB_WT_STRING, outer) ||
        !pb_encode_varint(&output, inner_header_size + size) ||
        !pb_encode_tag(&output, PB_WT_STRING, 1) || !pb_encode_varint(&output, size)) return false;
    size_t frame_size = output.bytes_written + size;
    if (frame_size > UINT16_MAX) return false;
    header[0] = frame_size >> 8;
    header[1] = frame_size;
    return transfer(header, output.bytes_written + 2, true, deadline) &&
           transfer(data, size, true, deadline);
}

struct setup_operation {
    struct wcom_operation op;
    const uint8_t *input;
    size_t input_size;
    uint8_t *output;
    size_t output_size;
    bool ok, reboot;
    SemaphoreHandle_t done;
};

static void dispatch(struct wcom_operation *base)
{
    struct setup_operation *op = (struct setup_operation *)base;
    op->ok = wble_setup_dispatch(op->input, op->input_size, op->output,
                                 WBLE_SETUP_MAX_RESPONSE, &op->output_size, &op->reboot);
    xSemaphoreGive(op->done);
    // The owner may reclaim op as soon as done is signaled.
}

void wble_setup_session(void)
{
    struct wble_setup_crypto crypto = {0};
    struct setup_operation op = {.op.func = dispatch};
    uint8_t *frame = NULL, *plain = NULL, *sealed = NULL;
    size_t frame_size = 0, plain_capacity = 0;
    uint32_t tag;
    struct wble_setup_span hello, peer;
    int64_t deadline = esp_timer_get_time() + 15000000;
    frame = read_frame(64, &frame_size, deadline);
    uint8_t public_key[32];
    if (!frame || !wble_setup_unwrap(frame, frame_size, &tag, &hello) || tag != 20 ||
        !wble_setup_unwrap(hello.data, hello.size, &tag, &peer) || tag != 1 || peer.size != 32 ||
        !wble_setup_crypto_accept(&crypto, peer.data, public_key) ||
        !write_bytes_message(21, public_key, sizeof public_key, deadline)) goto done;
    free(frame); frame = NULL;
    op.done = xSemaphoreCreateBinary();
    op.output = malloc(WBLE_SETUP_MAX_RESPONSE);
    sealed = malloc(WBLE_SETUP_MAX_RESPONSE + 28);
    if (!op.done || !op.output || !sealed) goto done;
    while (wble_l2cap_session_alive()) {
        deadline = esp_timer_get_time() + 120000000;
        frame = read_frame(WBLE_SETUP_MAX_CONFIG + 128, &frame_size, deadline);
        struct wble_setup_span message, data;
        if (!frame || !wble_setup_unwrap(frame, frame_size, &tag, &message) || tag != 21 ||
            !wble_setup_unwrap(message.data, message.size, &tag, &data) || tag != 1) break;
        plain_capacity = data.size;
        plain = malloc(plain_capacity);
        if (!plain || !wble_setup_crypto_open(&crypto, data.data, data.size,
                                             plain, plain_capacity, &op.input_size)) break;
        mbedtls_platform_zeroize(frame, frame_size); free(frame); frame = NULL;
        op.input = plain;
        wcom_core_exec(&op.op);
        // Serialized with USB reset/challenge/config on WendyCom's task.
        // It must finish before the input and operation can be released.
        xSemaphoreTake(op.done, portMAX_DELAY);
        mbedtls_platform_zeroize(plain, plain_capacity); free(plain); plain = NULL;
        size_t sealed_size = 0;
        bool sent = op.ok && wble_setup_crypto_seal(&crypto, op.output, op.output_size,
                                    sealed, WBLE_SETUP_MAX_RESPONSE + 28, &sealed_size) &&
                    write_bytes_message(22, sealed, sealed_size, esp_timer_get_time() + 15000000);
        mbedtls_platform_zeroize(op.output, WBLE_SETUP_MAX_RESPONSE);
        if (op.reboot || !sent) break;
    }
done:
    if (frame) { mbedtls_platform_zeroize(frame, frame_size); free(frame); }
    if (plain) { mbedtls_platform_zeroize(plain, plain_capacity); free(plain); }
    if (op.output) { mbedtls_platform_zeroize(op.output, WBLE_SETUP_MAX_RESPONSE); free(op.output); }
    if (sealed) { mbedtls_platform_zeroize(sealed, WBLE_SETUP_MAX_RESPONSE + 28); free(sealed); }
    if (op.done) vSemaphoreDelete(op.done);
    wble_setup_crypto_close(&crypto);
    if (op.reboot) {
        // Persistence closed setup even if the peer disconnected before ACK.
        // Boot starts certificate issuance from the stored one-use token.
        vTaskDelay(pdMS_TO_TICKS(250));
        esp_restart();
    }
}
