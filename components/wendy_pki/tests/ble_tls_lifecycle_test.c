/* Compile the real BLE TLS session owner and inject changes at its public
 * PKI boundary. Cryptographic handshakes are covered by tls_test_driver.go. */
#include "wendy_ble_tls.h"
#include "wendy_ble_l2cap.h"
#include "wendy_conf.h"
#include "wendy_pki.h"
#include "esp_timer.h"
#undef NDEBUG
#include <assert.h>
#include <stdlib.h>
#include <string.h>

struct wendy_pki_connection { unsigned generation; };
static wendy_pki_connection *live_connection;
static bool enrolled, resetting, current;
static unsigned accepts, closes, reads, writes, pending_checks, transport_calls;
static unsigned generation;
static struct wendy_pki_stream accepted_stream;
enum mutation { NO_CHANGE, RESET, CLEAR_ENROLLMENT, INVALIDATE_CACHE };
enum accept_mode { ACCEPT, REFUSE, CHANGE_DURING_WAIT, CHANGE_BEFORE_RETURN };
static enum mutation mutation, wait_mutation;
static enum accept_mode mode;

static void change(enum mutation action)
{
    switch (action) {
        case NO_CHANGE: break;
        case RESET: resetting = true; break;
        case CLEAR_ENROLLMENT: enrolled = false; break;
        case INVALIDATE_CACHE: current = false; break;
    }
}

bool wendy_conf_has_enrollment(void) { return enrolled; }
bool wendy_conf_is_current(void) { return current; }
bool wendy_pki_reset_in_progress(void) { return resetting; }
int64_t esp_timer_get_time(void) { return 1000000; }
bool wble_l2cap_session_alive(void) { return true; }
ssize_t wble_l2cap_read(void *data, size_t size)
{
    transport_calls++;
    memset(data, 'r', size);
    return (ssize_t)size;
}
ssize_t wble_l2cap_write(const void *data, size_t size)
{
    (void)data;
    transport_calls++;
    return (ssize_t)size;
}
static bool wait_transport(TickType_t ticks)
{
    assert(ticks > 0 && ticks <= pdMS_TO_TICKS(2000));
    transport_calls++;
    change(wait_mutation);
    wait_mutation = NO_CHANGE;
    return true;
}
bool wble_l2cap_wait_readable(TickType_t ticks) { return wait_transport(ticks); }
bool wble_l2cap_wait_writable(TickType_t ticks) { return wait_transport(ticks); }

/* Any attempt to fall back from enrolled PKI to anonymous TLS must
 * fail the test before a default certificate or private key is accessed. */
static struct wendy_conf_span unexpected_credential(void)
{
    assert(0 && "enrolled BLE fell back to anonymous TLS");
    return (struct wendy_conf_span){0};
}
struct wendy_conf_span wendy_conf_get_default_certificate(void) { return unexpected_credential(); }
struct wendy_conf_span wendy_conf_get_default_private_key(void) { return unexpected_credential(); }
size_t heap_caps_get_free_size(unsigned capabilities) { (void)capabilities; return 100000; }

esp_err_t wendy_pki_accept_stream(const struct wendy_pki_stream *stream,
                                wendy_pki_connection **connection)
{
    assert(!live_connection && !*connection);
    assert(stream && stream->read && stream->write && stream->wait);
    accepts++;
    accepted_stream = *stream;
    if (mode == REFUSE) return ESP_FAIL;

    char byte;
    assert(stream->read(stream->context, &byte, 1) == 1);
    assert(stream->write(stream->context, "x", 1) == 1);
    if (mode == CHANGE_DURING_WAIT) {
        wait_mutation = mutation;
        assert(stream->wait(stream->context, false, esp_timer_get_time() + 5000000) == -1);
        unsigned before = transport_calls;
        assert(stream->read(stream->context, &byte, 1) == WBLE_ERR_UNKNOWN);
        assert(stream->write(stream->context, "x", 1) == WBLE_ERR_UNKNOWN);
        assert(stream->wait(stream->context, true, esp_timer_get_time() + 5000000) == -1);
        assert(transport_calls == before);
        return ESP_FAIL;
    }
    assert(!stream->wait(stream->context, true, esp_timer_get_time() + 5000000));
    live_connection = calloc(1, sizeof *live_connection);
    assert(live_connection);
    live_connection->generation = ++generation;
    *connection = live_connection;
    if (mode == CHANGE_BEFORE_RETURN) change(mutation);
    return ESP_OK;
}
void wendy_pki_close(wendy_pki_connection *connection)
{
    if (!connection) return;
    assert(connection == live_connection);
    closes++;
    free(connection);
    live_connection = NULL;
}
ssize_t wendy_pki_read(void *connection, void *data, size_t size)
{
    assert(connection && connection == live_connection);
    reads++;
    memset(data, 'p', size);
    return (ssize_t)size;
}
ssize_t wendy_pki_write(void *connection, const void *data, size_t size)
{
    assert(connection && connection == live_connection);
    (void)data;
    writes++;
    return (ssize_t)size;
}
bool wendy_pki_pending(wendy_pki_connection *connection)
{
    assert(connection && connection == live_connection);
    pending_checks++;
    return true;
}

static esp_err_t start(void)
{
    /* The boot advertising policy remains enrolled even if the configuration
     * cache is invalidated by a later USB write. */
    return wble_tls_session_start(true);
}
static void assert_inactive(void)
{
    unsigned before = reads + writes + pending_checks;
    char byte;
    assert(wble_tls_read(&byte, 1) == WBLE_ERR_UNKNOWN);
    assert(wble_tls_write("x", 1) == WBLE_ERR_UNKNOWN);
    assert(!wble_tls_pending());
    assert(reads + writes + pending_checks == before);
}
static void end_twice(unsigned expected_closes)
{
    wble_tls_session_end();
    wble_tls_session_end();
    assert(!live_connection && closes == expected_closes);
    assert_inactive();
}
static void reset_fixture(void)
{
    assert(!live_connection);
    enrolled = true;
    current = true;
    resetting = false;
    accepts = closes = reads = writes = pending_checks = transport_calls = 0;
    mode = ACCEPT;
    mutation = wait_mutation = NO_CHANGE;
}
static void test_success_and_next_session(void)
{
    reset_fixture();
    assert(start() == ESP_OK);
    char byte;
    assert(wble_tls_read(&byte, 1) == 1 && byte == 'p');
    assert(wble_tls_write("x", 1) == 1 && wble_tls_pending());
    assert(reads == 1 && writes == 1 && pending_checks == 1);
    unsigned previous_generation = live_connection->generation;
    end_twice(1);
    assert(start() == ESP_OK);
    assert(live_connection->generation > previous_generation && accepts == 2);
    end_twice(2);
}
static void test_refusal(void)
{
    reset_fixture();
    mode = REFUSE;
    assert(start() == ESP_FAIL && accepts == 1);
    assert_inactive();
    end_twice(0);
    mode = ACCEPT;
    assert(start() == ESP_OK && accepts == 2);
    end_twice(1);
}
static void test_changes(enum mutation action)
{
    /* Reset or invalidated cache before a new connection must not replace
     * the enrolled boot policy with anonymous TLS or reach either backend. */
    reset_fixture();
    change(action);
    assert(start() == ESP_ERR_INVALID_STATE && accepts == 0);
    end_twice(0);

    reset_fixture();
    mode = CHANGE_DURING_WAIT;
    mutation = action;
    assert(start() != ESP_OK && accepts == 1);
    end_twice(0);

    reset_fixture();
    mode = CHANGE_BEFORE_RETURN;
    mutation = action;
    assert(start() == ESP_ERR_INVALID_STATE && accepts == 1 && closes == 1);
    end_twice(1);

    reset_fixture();
    assert(start() == ESP_OK);
    change(action);
    assert_inactive();
    char byte;
    unsigned before = transport_calls;
    assert(accepted_stream.read(accepted_stream.context, &byte, 1) == WBLE_ERR_UNKNOWN);
    assert(accepted_stream.write(accepted_stream.context, "x", 1) == WBLE_ERR_UNKNOWN);
    assert(transport_calls == before);
    /* Teardown must use the session's snapshot even when enrollment is now
     * false. The next accept checks that its output pointer was cleared. */
    end_twice(1);
    assert(start() == ESP_ERR_INVALID_STATE && accepts == 1);
    end_twice(1);
    enrolled = true;
    current = true;
    resetting = false;
    assert(start() == ESP_OK && accepts == 2);
    end_twice(2);
}
int main(void)
{
    test_success_and_next_session();
    test_refusal();
    test_changes(RESET);
    test_changes(CLEAR_ENROLLMENT);
    test_changes(INVALIDATE_CACHE);
    return 0;
}
