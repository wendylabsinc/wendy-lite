/* Exercise actual transport publication with an asynchronous/coalescing NPL
 * queue. SDK timer stop does not drain a callback already in progress. */
#define ble_npl_eventq_put base_eventq_put
#define esp_timer_stop base_timer_stop
#define esp_timer_restart base_timer_restart
#include "stubs/esp_timer.h"
#undef ble_npl_eventq_put
#undef esp_timer_stop
#undef esp_timer_restart
static void (*stop_preemption)(void);
static void (*put_preemption)(void);
static void (*restart_preemption)(void);
static bool drop_publication;
static inline void run_hook(void (**slot)(void))
{
    if (*slot) {
        void (*hook)(void) = *slot;
        *slot = NULL;
        hook();
    }
}
static inline void ble_npl_eventq_put(void *queue, struct ble_npl_event *event)
{
    run_hook(&put_preemption);
    assert(event->callback && "published a deinitialized NPL event");
    if (!drop_publication)
        base_eventq_put(queue, event);
}
static inline esp_err_t esp_timer_stop(esp_timer_handle_t timer)
{
    esp_err_t result = base_timer_stop(timer);
    run_hook(&stop_preemption);
    return result;
}
static inline esp_err_t esp_timer_restart(esp_timer_handle_t timer, uint64_t period)
{
    run_hook(&restart_preemption);
    return base_timer_restart(timer, period);
}
#define main original_fixture_main
#include "advertising_test.c"
#undef main
static uint8_t mesh[30];
static void enable(void)
{
    assert(!wendy_ble_mesh_advertisement(mesh, sizeof mesh));
    test_run_event();
    assert(_mesh_adv_timer && _mesh_adv_event.callback);
}
static void assert_off(void)
{
    assert(wendy_ble_mesh_advertisement_idle());
    assert(!_mesh_adv_timer && _mesh_adv_event.callback && _mesh_adv_event_initialized);
    assert(!test_queued_event);
    /* An old timer callback may start after stop/delete; it retains no event. */
    _mesh_adv_tick(NULL);
    assert(!test_queued_event);
}
static void disable_during_put(void)
{
    assert(!wendy_ble_mesh_advertisement(NULL, 0));
    test_run_event();
    assert(wendy_ble_mesh_advertisement_idle());
    assert(!_mesh_adv_timer && _mesh_adv_event.callback);
}
static void disable_during_restart(void)
{
    /* A setter cannot race host timer restart; it retries without blocking. */
    assert(wendy_ble_mesh_advertisement(NULL, 0) == ESP_ERR_INVALID_STATE);
}
int main(void)
{
    test_pki_enrollment();
    test_defer_events = true;
    enable();
    assert(!wendy_ble_mesh_advertisement(NULL, 0));
    assert(test_queued_event && _mesh_adv_timer);
    /* A previous OFF callback preempts a repeated OFF setter after stop. */
    stop_preemption = test_run_event;
    assert(!wendy_ble_mesh_advertisement(NULL, 0));
    test_run_event();
    assert_off();
    assert(!wendy_ble_mesh_advertisement(NULL, 0));

    enable();
    /* A timer callback has borrowed the event but not finished queueing. OFF
     * retires its timer while the host-owned event remains valid. */
    put_preemption = disable_during_put;
    _mesh_adv_tick(NULL);
    assert(test_queued_event);
    /* SDK-shaped dequeue/dispatch gap: queued is cleared before event_run
     * reads the backing event. Another OFF poll must leave it valid. */
    struct ble_npl_event *dequeued = test_queued_event;
    test_queued_event = NULL;
    dequeued->queued = false;
    assert(!wendy_ble_mesh_advertisement(NULL, 0));
    assert(dequeued->callback);
    dequeued->callback(dequeued);
    assert_off();

    enable();
    /* Queue saturation is recoverable through the existing shutdown poll. */
    drop_publication = true;
    assert(!wendy_ble_mesh_advertisement(NULL, 0));
    assert(!wendy_ble_mesh_advertisement_idle());
    drop_publication = false;
    assert(!wendy_ble_mesh_advertisement(NULL, 0));
    test_run_event();
    assert_off();

    enable();
    test_advertising_active = false;
    restart_preemption = disable_during_restart;
    _mesh_adv_tick(NULL);
    test_run_event();
    assert(!restart_preemption && test_advertising_active);
    assert(!wendy_ble_mesh_advertisement(NULL, 0));
    test_run_event();
    assert_off();

    /* Legal single-core scheduling: every put immediately preempts its
     * producer with the higher-priority NimBLE host. Repeated OFF still makes
     * progress without waiting for its publisher to resume. */
    test_defer_events = false;
    assert(!wendy_ble_mesh_advertisement(mesh, sizeof mesh));
    assert(!wendy_ble_mesh_advertisement(NULL, 0));
    assert(wendy_ble_mesh_advertisement_idle());
    assert(!wendy_ble_mesh_advertisement(NULL, 0));
    assert_off();
    assert(test_event_initializations == 1 && !test_event_deinitializations);
    reset_fixture();
    puts("Advertising OFF drains asynchronous publishers, queued refresh and restart ownership");
    return 0;
}
