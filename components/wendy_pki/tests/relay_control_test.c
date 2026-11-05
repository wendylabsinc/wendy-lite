/* Production control loop with deterministic TLS I/O and monotonic deadlines. */
#include "wendy_pki_internal.h"
#include "esp_timer.h"
#include <assert.h>
#include <sys/select.h>

static int control_read(mbedtls_ssl_context *, unsigned char *, size_t);
static int control_write(mbedtls_ssl_context *, const unsigned char *, size_t);
static int control_close_notify(mbedtls_ssl_context *);
static int control_select(int, fd_set *, fd_set *, fd_set *, struct timeval *);
#define mbedtls_ssl_read control_read
#define mbedtls_ssl_write control_write
#define mbedtls_ssl_close_notify control_close_notify
#define select control_select
#include "../src/wendy_pki_tls.c"
#undef mbedtls_ssl_read
#undef mbedtls_ssl_write
#undef mbedtls_ssl_close_notify
#undef select

enum scenario {
    RENEW,
    EARLY_TIMEOUT,
    EOF_AT_RENEW,
    BAD_HEADER_AT_RENEW,
    PARTIAL_AT_RENEW,
    WRITE_STALL_AT_RENEW,
    RESET_AT_RENEW,
    RESET_ON_TIMEOUT,
    WAIT_ERROR_AT_RENEW,
    HANDOFF,
    LONG_RUN
};
static enum scenario scenario;
static int64_t now, fetch_cost;
static unsigned heartbeats, heartbeat_target, replies, waits, read_phase, fetches;
static size_t key_offset;
static bool reset, partial_sent;
static const unsigned char key_set[7 + WENDY_LITE_KEY_BYTES] = {'W', 'R', 3, 4, 1, 1, 'k'};
int64_t esp_timer_get_time(void)
{
    return now;
}
bool wendy_pki_reset_in_progress(void)
{
    return reset;
}
static int control_read(mbedtls_ssl_context *ssl, unsigned char *out, size_t size)
{
    (void)ssl;
    if (key_offset < sizeof key_set) {
        size_t count = sizeof key_set - key_offset;
        if (count > size)
            count = size;
        memcpy(out, key_set + key_offset, count);
        key_offset += count;
        return (int)count;
    }
    if (scenario == HANDOFF) {
        if (read_phase++ == 0) {
            assert(size == 4);
            memcpy(out, "WR\x03\x03", 4);
            return 4;
        }
        if (read_phase <= 3) {
            memset(out, 7, size);
            return (int)size;
        }
        return MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY;
    }
    if (scenario != EARLY_TIMEOUT && heartbeats < heartbeat_target) {
        assert(size == 4);
        now += 29000000;
        heartbeats++;
        memcpy(out, "WR\x03\x01", 4);
        return 4;
    }
    if (scenario == EOF_AT_RENEW) {
        now = 240000000;
        return 0;
    }
    if (scenario == BAD_HEADER_AT_RENEW) {
        now = 240000000;
        assert(size == 4);
        memcpy(out, "BAD!", 4);
        return 4;
    }
    if (scenario == PARTIAL_AT_RENEW && !partial_sent) {
        partial_sent = true;
        *out = 'W';
        return 1;
    }
    if (scenario == RESET_AT_RENEW) {
        now = 240000000;
        reset = true;
    }
    return scenario == WRITE_STALL_AT_RENEW ? MBEDTLS_ERR_SSL_WANT_WRITE
                                            : MBEDTLS_ERR_SSL_WANT_READ;
}
static int control_write(mbedtls_ssl_context *ssl, const unsigned char *out, size_t size)
{
    (void)ssl;
    assert(size == 4 && !memcmp(out, "WR\x03\x02", 4));
    replies++;
    return (int)size;
}
static int control_close_notify(mbedtls_ssl_context *ssl)
{
    (void)ssl;
    return 0;
}
static int control_select(int nfds, fd_set *rd, fd_set *wr, fd_set *ex, struct timeval *timeout)
{
    (void)rd;
    (void)wr;
    assert(nfds == 11 && !ex && timeout);
    now += (int64_t)timeout->tv_sec * 1000000 + timeout->tv_usec;
    waits++;
    if (scenario == RESET_ON_TIMEOUT)
        reset = true;
    return scenario == WAIT_ERROR_AT_RENEW ? -1 : 0;
}
static void run(enum scenario which, int expected)
{
    scenario = which;
    now = 0;
    heartbeats = replies = waits = read_phase = 0;
    heartbeat_target = 8;
    key_offset = 0;
    reset = partial_sent = false;
    wendy_pki_connection connection = {.fd = 10, .renew_deadline_us = 240000000};
    struct wendy_lite_trust trust;
    assert(wendy_pki_relay_upgrade(&connection, &trust) == expected);
    assert(trust.count == 1 && trust.keys[0].id_size == 1 && trust.keys[0].id[0] == 'k');
    assert(connection.fd == (which == HANDOFF ? -1 : 10));
    if (which == HANDOFF) {
        assert(trust.session[0] == 7 && trust.grant_hash[0] == 7 && !waits);
    } else {
        assert(replies == heartbeats);
        assert(heartbeats == (which == EARLY_TIMEOUT ? 0 : 8));
        assert(now == (which == EARLY_TIMEOUT ? 30000000 : 240000000));
    }
}
static void count_fetch(void)
{
    /* The pong of the current heartbeat went out first. */
    assert(replies == heartbeats);
    fetches++;
    now += fetch_cost;
}
/* One heartbeat every 29 s, then silence. */
static void run_long(int64_t renew, unsigned count, int64_t cost, void (*hook)(void), int expected,
                     unsigned expected_fetches)
{
    scenario = LONG_RUN;
    now = 0;
    heartbeats = replies = waits = read_phase = fetches = 0;
    heartbeat_target = count;
    fetch_cost = cost;
    key_offset = 0;
    reset = partial_sent = false;
    wendy_pki_connection connection = {.fd = 10, .renew_deadline_us = renew, .refresh_time = hook};
    struct wendy_lite_trust trust;
    assert(wendy_pki_relay_upgrade(&connection, &trust) == expected);
    assert(heartbeats == count && replies == count && fetches == expected_fetches);
}
int main(void)
{
    /* No renewal date: the connection stays open past the old 240 s limit, and
     * silence is a failure, not a planned stop. */
    run_long(0, 100, 0, count_fetch, WENDY_PKI_RELAY_FAILED, 0);
    assert(now == (100 * 29 + 30) * INT64_C(1000000));
    /* One fetch per hour, counted from the end of the previous fetch. */
    const int64_t five_s = 5000000;
    run_long(0, 124, five_s, count_fetch, WENDY_PKI_RELAY_FAILED, 0);
    run_long(0, 125, five_s, count_fetch, WENDY_PKI_RELAY_FAILED, 1);
    run_long(0, 249, five_s, count_fetch, WENDY_PKI_RELAY_FAILED, 1);
    run_long(0, 250, five_s, count_fetch, WENDY_PKI_RELAY_FAILED, 2);
    run_long(0, 130, 0, NULL, WENDY_PKI_RELAY_FAILED, 0);
    /* The heartbeat at 3625 s crosses the renewal date: no fetch, only the stop. */
    run_long(INT64_C(3610000000), 125, five_s, count_fetch, WENDY_PKI_RELAY_RENEW, 0);
    /* A slow fetch crosses the renewal date: the stop follows it. */
    run_long(INT64_C(3640000000), 125, 30000000, count_fetch, WENDY_PKI_RELAY_RENEW, 1);
    run(RENEW, WENDY_PKI_RELAY_RENEW);
    run(EARLY_TIMEOUT, WENDY_PKI_RELAY_FAILED);
    run(EOF_AT_RENEW, WENDY_PKI_RELAY_FAILED);
    run(BAD_HEADER_AT_RENEW, WENDY_PKI_RELAY_FAILED);
    run(PARTIAL_AT_RENEW, WENDY_PKI_RELAY_FAILED);
    run(WRITE_STALL_AT_RENEW, WENDY_PKI_RELAY_FAILED);
    run(RESET_AT_RENEW, WENDY_PKI_RELAY_FAILED);
    run(RESET_ON_TIMEOUT, WENDY_PKI_RELAY_FAILED);
    run(WAIT_ERROR_AT_RENEW, WENDY_PKI_RELAY_FAILED);
    run(HANDOFF, 10);
    puts("PASS open control connection, hourly time fetch, planned stop, failure deadlines and "
         "detached handoff");
}
