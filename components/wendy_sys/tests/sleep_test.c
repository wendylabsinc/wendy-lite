#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef void *wasm_exec_env_t;
typedef uint32_t TickType_t;
#define pdMS_TO_TICKS(ms) ((TickType_t)(ms) / TICK_MS)

static bool terminating;
static TickType_t elapsed, stop_at, busy_until;
static unsigned delay_calls;

static bool wendy_wasm_is_terminating(void)
{
    return terminating;
}

static TickType_t xTaskGetTickCount(void)
{
    return elapsed;
}

static void vTaskDelay(TickType_t ticks)
{
    assert(ticks > 0);
    elapsed += ticks;
    /* A higher-priority task can prevent execution after the block expires. */
    if (elapsed < busy_until)
        elapsed = busy_until;
    delay_calls++;
    if (stop_at && elapsed >= stop_at) {
        terminating = true;
    }
}

#include "sleep_production.inc"

static void reset(bool stopped)
{
    terminating = stopped;
    elapsed = stop_at = busy_until = delay_calls = 0;
}

int main(void)
{
    TickType_t quantum = pdMS_TO_TICKS(25);
    if (!quantum) quantum = 1;

    /* A stop arrives while the guest is inside a minute-long host sleep. */
    reset(false);
    stop_at = 1;
    sys_sleep_ms_wrapper(NULL, 60000);
    assert(terminating);
    assert(elapsed <= quantum);

    reset(true);
    sys_sleep_ms_wrapper(NULL, 60000);
    assert(delay_calls == 0);

    /* Ordinary sleeps retain their original tick conversion and minimum. */
    reset(false);
    sys_sleep_ms_wrapper(NULL, 250);
    assert(elapsed == pdMS_TO_TICKS(250));

    /* Time ready but not scheduled counts toward the requested duration. */
    reset(false);
    busy_until = pdMS_TO_TICKS(2000);
    sys_sleep_ms_wrapper(NULL, 1000);
    assert(elapsed == busy_until);
    assert(delay_calls == 1);

    reset(false);
    busy_until = pdMS_TO_TICKS(500);
    sys_sleep_ms_wrapper(NULL, 1000);
    assert(elapsed == pdMS_TO_TICKS(1000));

    /* Unsigned elapsed arithmetic must also handle a tick counter wrap. */
    reset(false);
    elapsed = UINT32_MAX - pdMS_TO_TICKS(100);
    TickType_t started = elapsed;
    sys_sleep_ms_wrapper(NULL, 500);
    assert((TickType_t)(elapsed - started) == pdMS_TO_TICKS(500));

    reset(false);
    sys_sleep_ms_wrapper(NULL, 1);
    assert(elapsed == 1);

    reset(false);
    sys_sleep_ms_wrapper(NULL, 0);
    sys_sleep_ms_wrapper(NULL, -1);
    assert(delay_calls == 0);

    printf("PASS host sleep cancellation and duration: %u ms ticks\n", TICK_MS);
    return 0;
}
