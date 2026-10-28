#include "wendy_ble_setup.h"
#include "wendy_ble_setup_crypto.h"
#include "wendy_ble_setup_wire.h"
#include "wendy_ble_l2cap.h"
#include "wendy_com_link.h"
#include "freertos/semphr.h"
#include "setup_wire_fixture.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint8_t input[1024], output[1024];
static size_t input_size, consumed, output_size;
static unsigned dispatches, decrypts, restarts;
static int64_t clock_us;
static bool stalled, should_reboot, fail_write;
int64_t esp_timer_get_time(void) { return clock_us += 100; }
void vTaskDelay(TickType_t ticks) { clock_us += ticks * 1000; }
bool wble_l2cap_session_alive(void) { return true; }
ssize_t wble_l2cap_read(void *out, size_t size) {
    if (stalled) return WBLE_ERR_WANT_READ;
    if (size > 3) size = 3; // Deliberately fragment length prefixes and protobufs.
    if (size > input_size - consumed) size = input_size - consumed;
    memcpy(out, input + consumed, size); consumed += size;
    return size;
}
ssize_t wble_l2cap_write(const void *data, size_t size) {
    if (fail_write && dispatches) return -1;
    if (size > 7) size = 7;
    assert(output_size + size <= sizeof output);
    memcpy(output + output_size, data, size); output_size += size; return size;
}
bool wble_l2cap_wait_readable(TickType_t timeout) { clock_us += timeout * 1000; return false; }
bool wble_l2cap_wait_writable(TickType_t timeout) { clock_us += timeout * 1000; return false; }
SemaphoreHandle_t xSemaphoreCreateBinary(void) { return calloc(1, 1); }
void vSemaphoreDelete(SemaphoreHandle_t s) { free(s); }
int xSemaphoreGive(SemaphoreHandle_t s) { *(char *)s = 1; return 1; }
int xSemaphoreTake(SemaphoreHandle_t s, TickType_t t) { assert(*(char *)s); *(char *)s = 0; return 1; }
void wcom_core_exec(struct wcom_operation *op) { op->func(op); }
void esp_restart(void) { ++restarts; }
/* The crypto backend has a separate real PSA interoperability test. Here its
 * boundary is deterministic so fragmented framing and dispatch can be tested. */
bool wble_setup_crypto_accept(struct wble_setup_crypto *s, const uint8_t peer[32], uint8_t pub[32]) {
    assert(!memcmp(peer, fixture_client, 32)); memcpy(pub, fixture_server, 32); return true;
}
bool wble_setup_crypto_open(struct wble_setup_crypto *s, const uint8_t *in, size_t n, uint8_t *out, size_t cap, size_t *size) {
    if (decrypts++) return false;
    assert(n == sizeof fixture_request && !memcmp(in, fixture_request, n));
    assert(cap >= 13); memcpy(out, "wifi password", 13); *size = 13; return true;
}
bool wble_setup_crypto_seal(struct wble_setup_crypto *s, const uint8_t *in, size_t n, uint8_t *out, size_t cap, size_t *size) {
    assert(n == 9 && !memcmp(in, "connected", n));
    assert(cap >= sizeof fixture_response); memcpy(out, fixture_response, sizeof fixture_response);
    *size = sizeof fixture_response; return true;
}
void wble_setup_crypto_close(struct wble_setup_crypto *s) { memset(s, 0, sizeof *s); }
bool wble_setup_dispatch(const uint8_t *in, size_t n, uint8_t *out, size_t cap, size_t *size, bool *reboot) {
    assert(n == 13 && !memcmp(in, "wifi password", n)); assert(cap >= 9);
    memcpy(out, "connected", 9); *size = 9; *reboot = should_reboot; ++dispatches; return true;
}
static void reset(void) {
    input_size = consumed = output_size = dispatches = decrypts = restarts = 0;
    clock_us = 0; stalled = should_reboot = fail_write = false;
}
static void append(uint32_t outer, const uint8_t *data, size_t size) {
    uint8_t inner[256]; size_t inner_size, full_size;
    assert(wble_setup_wrap(1, data, size, inner, sizeof inner, &inner_size));
    assert(wble_setup_wrap(outer, inner, inner_size, input + input_size + 2,
                           sizeof input - input_size - 2, &full_size));
    input[input_size] = full_size >> 8; input[input_size + 1] = full_size;
    input_size += 2 + full_size;
}
int main(void) {
    reset(); append(20, fixture_client, sizeof fixture_client); append(21, fixture_request, sizeof fixture_request);
    wble_setup_session();
    assert(dispatches == 1 && !restarts && consumed == input_size);
    size_t first_size = output[0] * 256 + output[1];
    uint32_t tag; struct wble_setup_span body, bytes;
    assert(wble_setup_unwrap(output + 2, first_size, &tag, &body) && tag == 21);
    assert(wble_setup_unwrap(body.data, body.size, &tag, &bytes) && tag == 1 && bytes.size == 32);
    assert(!memcmp(bytes.data, fixture_server, 32));
    size_t next = first_size + 2, next_size = output[next] * 256 + output[next + 1];
    assert(next + 2 + next_size == output_size);
    assert(wble_setup_unwrap(output + next + 2, next_size, &tag, &body) && tag == 22);
    assert(wble_setup_unwrap(body.data, body.size, &tag, &bytes) && tag == 1);
    assert(bytes.size == sizeof fixture_response && !memcmp(bytes.data, fixture_response, bytes.size));
    reset(); append(21, fixture_request, sizeof fixture_request); wble_setup_session();
    assert(!dispatches && !output_size); // Cannot send sealed data before hello.
    reset(); append(20, fixture_client, sizeof fixture_client); append(18, NULL, 0); wble_setup_session();
    assert(!dispatches && !decrypts); // Cannot send plaintext after hello.
    reset(); append(20, fixture_client, sizeof fixture_client); --input_size; wble_setup_session();
    assert(!dispatches && !output_size); // Truncated hello.
    reset(); input[0] = 255; input[1] = 255; input_size = 2; wble_setup_session();
    assert(!dispatches && !output_size); // Oversized first frame rejected before allocation.
    reset(); stalled = true; wble_setup_session();
    assert(clock_us >= 15000000 && clock_us < 15200000 && !dispatches);
    reset(); append(20, fixture_client, sizeof fixture_client); append(21, fixture_request, sizeof fixture_request);
    append(21, fixture_request, sizeof fixture_request); wble_setup_session(); assert(dispatches == 1);
    reset(); should_reboot = fail_write = true;
    append(20, fixture_client, sizeof fixture_client); append(21, fixture_request, sizeof fixture_request);
    wble_setup_session(); assert(dispatches == 1 && restarts == 1); // Persisted setup survives a lost ACK.
    puts("BLE setup framing, plaintext rejection, timeout and lost-ACK tests passed");
}
