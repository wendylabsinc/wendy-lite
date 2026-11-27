/* Exercise the production worker with deterministic PKI and scheduler outcomes. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>

static void *worker_calloc(size_t count, size_t size);
static int worker_close(int fd);
#define calloc worker_calloc
#define close worker_close
#include "../src/wendy_cloud.c"
#undef calloc
#undef close

struct wendy_pki_connection {
    int fd;
};
struct step {
    bool allocation_fails, connection_fails, stop_after_connect, stop_after_upgrade;
    int result;
    unsigned delays_before, failures_after;
    unsigned up_ms; /* how long the control connection stays up */
};
static const struct step *steps;
static size_t step_count, attempts;
/* Each reconnect delay in order; a woken delay models a network change. */
static const unsigned *expected_delays;
static const bool *woken;
static size_t expected_delay_count;
static struct wendy_pki_connection connection;
static TickType_t ticks;
static unsigned connects, closes, delays, handoffs, dropped_fds, completed;
static bool connection_owned;

static const struct step *current(void)
{
    assert(attempts && attempts <= step_count);
    return &steps[attempts - 1];
}
static void *worker_calloc(size_t count, size_t size)
{
    attempts++;
    assert(delays == current()->delays_before);
    assert(!connection_owned && s_outer_fd == -1);
    return current()->allocation_fails ? NULL : calloc(count, size);
}
static int worker_close(int fd)
{
    assert(fd == 0 && atomic_load(&s_stop));
    dropped_fds++;
    return 0;
}
bool wendy_conf_has_enrollment(void)
{
    return true;
}
SemaphoreHandle_t xSemaphoreCreateBinary(void)
{
    return (void *)1;
}
BaseType_t xTaskCreatePinnedToCore(void (*entry)(void *), const char *name, unsigned stack,
                                   void *arg, unsigned priority, TaskHandle_t *handle,
                                   unsigned core)
{
    (void)entry;
    (void)name;
    (void)stack;
    (void)arg;
    (void)priority;
    (void)handle;
    (void)core;
    return pdPASS;
}
BaseType_t xSemaphoreTake(SemaphoreHandle_t handle, TickType_t ticks)
{
    assert(handle == s_wake && delays < expected_delay_count && ticks == expected_delays[delays]);
    assert(wendy_cloud_get_state() == WENDY_CLOUD_STATE_DISCONNECTED);
    assert(wendy_cloud_connect_failures() == current()->failures_after);
    assert(!connection_owned && s_outer_fd == -1);
    bool wake = woken && woken[delays];
    delays++;
    return wake ? pdTRUE : pdFALSE;
}
BaseType_t xSemaphoreGive(SemaphoreHandle_t handle)
{
    assert(handle == s_stopped);
    completed++;
    return pdTRUE;
}
TickType_t xTaskGetTickCount(void)
{
    return ticks;
}
void vTaskDelete(TaskHandle_t task)
{
    assert(!task);
}
esp_err_t wendy_pki_connect(wendy_pki_connection **out)
{
    connects++;
    assert(!*out && wendy_cloud_get_state() == WENDY_CLOUD_STATE_CONNECTING);
    if (current()->stop_after_connect)
        atomic_store(&s_stop, true);
    if (current()->connection_fails)
        return ESP_FAIL;
    connection.fd = 100;
    connection_owned = true;
    *out = &connection;
    return ESP_OK;
}
int wendy_pki_fd(void *outer)
{
    assert(outer == &connection && connection_owned);
    return connection.fd;
}
int wendy_pki_relay_upgrade(wendy_pki_connection *outer, struct wendy_lite_trust *trust)
{
    assert(outer == &connection && trust && connection_owned);
    assert(s_outer_fd == connection.fd && wendy_cloud_is_connected());
    assert(!wendy_cloud_connect_failures());
    ticks += current()->up_ms;
    if (current()->stop_after_upgrade)
        atomic_store(&s_stop, true);
    if (current()->result >= 0)
        connection.fd = -1; /* Detached fd belongs to caller. */
    return current()->result;
}
void wendy_pki_close(wendy_pki_connection *outer)
{
    assert(s_outer_fd == -1);
    if (!outer)
        return;
    assert(outer == &connection && connection_owned);
    connection_owned = false;
    closes++;
}
void wendy_server_accept_operator(int fd, const struct wendy_lite_trust *trust)
{
    assert(fd == 0 && trust && !connection_owned && !atomic_load(&s_stop));
    handoffs++;
}
static void run_with_delays(const struct step *plan, size_t count, const unsigned *delays_ms,
                            const bool *wakes, size_t delay_count)
{
    expected_delays = delays_ms;
    woken = wakes;
    expected_delay_count = delay_count;
    steps = plan;
    step_count = count;
    attempts = connects = closes = delays = handoffs = dropped_fds = completed = 0;
    atomic_store(&s_stop, false);
    atomic_store(&s_failures, 0);
    s_wake = (void *)2;
    s_stopped = (void *)3;
    s_task = (void *)4;
    cloud_task(NULL);
    assert(attempts == count && completed == 1 && !s_task && s_outer_fd == -1);
    assert(!connection_owned && wendy_cloud_get_state() == WENDY_CLOUD_STATE_IDLE);
    assert(wendy_cloud_connect_failures() == plan[count - 1].failures_after);
    assert(delays == delay_count);
}
#define RUN(plan, ...)                                                                         \
    do {                                                                                       \
        static const unsigned d_[] = {0, __VA_ARGS__};                                         \
        run_with_delays(plan, sizeof plan / sizeof *plan, d_ + 1, NULL, sizeof d_ / sizeof *d_ - 1); \
    } while (0)
int main(void)
{
    const struct step lifecycle[] = {
        {.connection_fails = true, .failures_after = 1},
        {.allocation_fails = true, .delays_before = 1, .failures_after = 2},
        {.result = WENDY_PKI_RELAY_RENEW, .delays_before = 2},
        {.result = WENDY_PKI_RELAY_FAILED, .delays_before = 2},
        {.result = -99, .delays_before = 3},
        {.result = 0, .delays_before = 4},
        {.result = WENDY_PKI_RELAY_RENEW, .delays_before = 4, .stop_after_upgrade = true},
    };
    /* Consecutive failures double the delay; a planned renewal or a handoff
     * starts the next failure at the configured delay again. */
    RUN(lifecycle, 5000, 10000, 5000, 10000);
    assert(connects == 6 && closes == 5 && delays == 4 && handoffs == 1 && !dropped_fds);
    const struct step stopped_handoff[] = {{.result = 0, .stop_after_upgrade = true}};
    run_with_delays(stopped_handoff, 1, NULL, NULL, 0);
    assert(connects == 1 && closes == 1 && !delays && !handoffs && dropped_fds == 1);
    const struct step stopped_connect[] = {{.connection_fails = true, .stop_after_connect = true}};
    run_with_delays(stopped_connect, 1, NULL, NULL, 0);
    assert(connects == 1 && !closes && !delays && !handoffs && !dropped_fds);

    /* A broker that keeps failing the control handshake is retried at most
     * once a minute, so it does not cost a TLS handshake every few seconds. */
    const struct step refused[] = {
        {.result = WENDY_PKI_RELAY_FAILED},
        {.result = WENDY_PKI_RELAY_FAILED, .delays_before = 1},
        {.result = WENDY_PKI_RELAY_FAILED, .delays_before = 2},
        {.result = WENDY_PKI_RELAY_FAILED, .delays_before = 3},
        {.result = WENDY_PKI_RELAY_FAILED, .delays_before = 4},
        {.result = WENDY_PKI_RELAY_FAILED, .delays_before = 5},
        {.result = WENDY_PKI_RELAY_FAILED, .delays_before = 6},
        {.result = WENDY_PKI_RELAY_RENEW, .delays_before = 7, .stop_after_upgrade = true},
    };
    RUN(refused, 5000, 10000, 20000, 40000, 60000, 60000, 60000);

    /* A network change wakes the wait early and starts again from the
     * configured delay. */
    const struct step network_change[] = {
        {.result = WENDY_PKI_RELAY_FAILED},
        {.result = WENDY_PKI_RELAY_FAILED, .delays_before = 1},
        {.result = WENDY_PKI_RELAY_FAILED, .delays_before = 2},
        {.result = WENDY_PKI_RELAY_RENEW, .delays_before = 3, .stop_after_upgrade = true},
    };
    static const unsigned change_delays[] = {5000, 10000, 5000};
    static const bool change_wakes[] = {false, true, false};
    run_with_delays(network_change, 4, change_delays, change_wakes, 3);

    /* Losing a connection that stayed up longer than the longest delay starts
     * again from the configured delay, even after a run of failures. */
    const struct step healthy_drop[] = {
        {.result = WENDY_PKI_RELAY_FAILED},
        {.result = WENDY_PKI_RELAY_FAILED, .delays_before = 1},
        {.result = WENDY_PKI_RELAY_FAILED, .delays_before = 2},
        {.result = WENDY_PKI_RELAY_FAILED, .delays_before = 3, .up_ms = 60000},
        {.result = WENDY_PKI_RELAY_FAILED, .delays_before = 4, .up_ms = 59999},
        {.result = WENDY_PKI_RELAY_RENEW, .delays_before = 5, .stop_after_upgrade = true},
    };
    RUN(healthy_drop, 5000, 10000, 20000, 5000, 10000);
    puts("PASS worker renewal, retry backoff, allocation failure, handoff and stop ownership");
}
