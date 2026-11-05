/* Exercise the production worker with the tunnel off. It keeps the time and the
 * identity current on one task, and it opens no broker connection. */
#include <assert.h>
#include <stdio.h>

#include "../src/wendy_cloud.c"

struct step {
    esp_err_t result;
    bool stop_in_check;
    unsigned failures_after;
    TickType_t wait;
};
enum { HOUR = 3600000, MINUTE = 60000 };

static const struct step *steps;
static size_t step_count, checks;
static unsigned waits, wakes, completed;

static const struct step *current(void)
{
    assert(checks && checks <= step_count);
    return &steps[checks - 1];
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
    assert(handle == s_wake && ticks == current()->wait);
    assert(wendy_cloud_get_state() == WENDY_CLOUD_STATE_DISCONNECTED);
    assert(!wendy_cloud_is_connected());
    assert(wendy_cloud_connect_failures() == current()->failures_after);
    waits++;
    if (checks == step_count)
        atomic_store(&s_stop, true);
    return pdFALSE;
}
BaseType_t xSemaphoreGive(SemaphoreHandle_t handle)
{
    if (handle == s_wake)
        wakes++;
    else if (handle == s_stopped)
        completed++;
    else
        assert(false);
    return pdTRUE;
}
void vTaskDelete(TaskHandle_t task)
{
    assert(!task);
}
esp_err_t wendy_pki_maintain(void)
{
    checks++;
    assert(wendy_cloud_get_state() == WENDY_CLOUD_STATE_CONNECTING);
    if (current()->stop_in_check)
        atomic_store(&s_stop, true);
    return current()->result;
}
static void run(const struct step *plan, size_t count)
{
    steps = plan;
    step_count = count;
    checks = waits = completed = 0;
    atomic_store(&s_stop, false);
    atomic_store(&s_failures, 0);
    s_wake = (void *)2;
    s_stopped = (void *)3;
    s_task = (void *)4;
    cloud_task(NULL);
    assert(checks == count && completed == 1 && !s_task);
    assert(wendy_cloud_get_state() == WENDY_CLOUD_STATE_IDLE);
    assert(wendy_cloud_connect_failures() == plan[count - 1].failures_after);
}
int main(void)
{
    /* One hour after success, one minute after failure. The count of failures
     * has a limit, and a success clears it. */
    const struct step lifecycle[] = {
        {.result = ESP_OK, .wait = HOUR},
        {.result = ESP_FAIL, .failures_after = 1, .wait = MINUTE},
        {.result = ESP_ERR_INVALID_STATE, .failures_after = 2, .wait = MINUTE},
        {.result = ESP_FAIL, .failures_after = 3, .wait = MINUTE},
        {.result = ESP_FAIL, .failures_after = 3, .wait = MINUTE},
        {.result = ESP_OK, .wait = HOUR},
    };
    run(lifecycle, sizeof lifecycle / sizeof *lifecycle);
    assert(waits == 6);

    /* A stop during a check does not wait for the next check, and it does not
     * count as a failure. */
    const struct step stopped[] = {{.result = ESP_FAIL, .stop_in_check = true}};
    run(stopped, 1);
    assert(!waits);

    /* A route change wakes the task. There is no broker socket to shut down. */
    wakes = 0;
    wendy_cloud_network_changed();
    assert(wakes == 1 && s_outer_fd == -1);
    puts("PASS worker check period, retry delay, failure count, stop and wake");
}
