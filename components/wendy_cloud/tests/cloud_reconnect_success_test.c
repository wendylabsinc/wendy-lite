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

struct wendy_pki_connection { int fd; };
struct step {
    bool allocation_fails, connection_fails, stop_after_connect, stop_after_upgrade;
    int result;
    unsigned delays_before, failures_after;
};
static const struct step *steps;
static size_t step_count, attempts;
static struct wendy_pki_connection connection;
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
bool wendy_conf_has_enrollment(void) { return true; }
SemaphoreHandle_t xSemaphoreCreateBinary(void) { return (void *)1; }
BaseType_t xTaskCreatePinnedToCore(void (*entry)(void *), const char *name,
    unsigned stack, void *arg, unsigned priority, TaskHandle_t *handle, unsigned core)
{
    (void)entry; (void)name; (void)stack; (void)arg;
    (void)priority; (void)handle; (void)core;
    return pdPASS;
}
BaseType_t xSemaphoreTake(SemaphoreHandle_t handle, TickType_t ticks)
{
    assert(handle == s_wake && ticks == 5000);
    assert(wendy_cloud_get_state() == WENDY_CLOUD_STATE_DISCONNECTED);
    assert(wendy_cloud_connect_failures() == current()->failures_after);
    assert(!connection_owned && s_outer_fd == -1);
    delays++;
    return pdTRUE;
}
BaseType_t xSemaphoreGive(SemaphoreHandle_t handle)
{
    assert(handle == s_stopped);
    completed++;
    return pdTRUE;
}
void vTaskDelete(TaskHandle_t task) { assert(!task); }
esp_err_t wendy_pki_connect(wendy_pki_connection **out)
{
    connects++;
    assert(!*out && wendy_cloud_get_state() == WENDY_CLOUD_STATE_CONNECTING);
    if (current()->stop_after_connect) atomic_store(&s_stop, true);
    if (current()->connection_fails) return ESP_FAIL;
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
    if (current()->stop_after_upgrade) atomic_store(&s_stop, true);
    if (current()->result >= 0) connection.fd = -1; /* Detached fd belongs to caller. */
    return current()->result;
}
void wendy_pki_close(wendy_pki_connection *outer)
{
    assert(s_outer_fd == -1);
    if (!outer) return;
    assert(outer == &connection && connection_owned);
    connection_owned = false;
    closes++;
}
void wendy_server_accept_operator(int fd, const struct wendy_lite_trust *trust)
{
    assert(fd == 0 && trust && !connection_owned && !atomic_load(&s_stop));
    handoffs++;
}
static void run(const struct step *plan, size_t count)
{
    steps = plan;
    step_count = count;
    attempts = connects = closes = delays = handoffs = dropped_fds = completed = 0;
    atomic_store(&s_stop, false);
    atomic_store(&s_failures, 0);
    s_wake = (void *)2; s_stopped = (void *)3; s_task = (void *)4;
    cloud_task(NULL);
    assert(attempts == count && completed == 1 && !s_task && s_outer_fd == -1);
    assert(!connection_owned && wendy_cloud_get_state() == WENDY_CLOUD_STATE_IDLE);
    assert(wendy_cloud_connect_failures() == plan[count - 1].failures_after);
}
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
    run(lifecycle, sizeof lifecycle / sizeof *lifecycle);
    assert(connects == 6 && closes == 5 && delays == 4 && handoffs == 1 && !dropped_fds);
    const struct step stopped_handoff[] = {{.result = 0, .stop_after_upgrade = true}};
    run(stopped_handoff, 1);
    assert(connects == 1 && closes == 1 && !delays && !handoffs && dropped_fds == 1);
    const struct step stopped_connect[] = {{.connection_fails = true, .stop_after_connect = true}};
    run(stopped_connect, 1);
    assert(connects == 1 && !closes && !delays && !handoffs && !dropped_fds);
    puts("PASS worker renewal, retry delays, allocation failure, handoff and stop ownership");
}
