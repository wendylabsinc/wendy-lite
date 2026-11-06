/* Ordinary management/actor scheduling with the exact production functions. */
#include "topology_query.h"
#include "wendy_net_alloc.h"
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
typedef void *TaskHandle_t;
struct wnrs {
    unsigned id;
};
struct wnrs_node {
    unsigned unused;
};
struct peer_state {
    struct wnrs_node *router_node;
    struct wnrs *router;
    struct peer_state *next;
    struct {
        unsigned medium;
    } candidate;
#if WN_CARRIER_OBSERVATION_ENABLED
    uint64_t attachment;
    atomic_bool active, setup_pending;
    bool failed, setup_waiting;
    struct { bool cancel, lent; } tls_state;
    void *connection;
#endif
};
static _Atomic(struct peer_state *) state;
static atomic_bool stopping;
static pthread_mutex_t state_lock = PTHREAD_MUTEX_INITIALIZER;
static _Thread_local TaskHandle_t task_id = (void *)2;
static atomic_llong clock_us;
static atomic_uint wakes;
static atomic_bool picked, hold, finish;
#if WN_CARRIER_OBSERVATION_ENABLED
static atomic_bool print_hold, print_entered, print_finish, fail_observation_alloc;
static atomic_uint printed_rows, rejected_observation_allocations;
static bool projection_error;
#endif
static TaskHandle_t xTaskGetCurrentTaskHandle(void)
{
    return task_id;
}
static int64_t esp_timer_get_time(void)
{
    return atomic_load(&clock_us);
}
static void tick(void)
{
    struct timespec wait = {.tv_nsec = 1000000};
    nanosleep(&wait, NULL);
}
static void vTaskDelay(unsigned ticks)
{
    assert(ticks == 1);
    atomic_fetch_add(&clock_us, 10000);
    tick();
}
static void wnad_wake(void)
{
    atomic_fetch_add(&wakes, 1);
}
static void wendy_conf_enrollment_identity(char tenant[37], char device[65])
{
    strcpy(tenant, "11111111-1111-4111-8111-111111111111");
    strcpy(device, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
}
static int wn_uuid_parse(const char *text, uint8_t out[16])
{
    assert(strlen(text) == 36);
    memset(out, text[0], 16);
    return 0;
}
static uint64_t wnrs_link_id(const struct wnrs *link)
{
    return link->id;
}
static int wnrs_topology(struct wnrs_node *node, uint32_t cursor, uint64_t generation,
                         WendyComNetTopologyPage *page)
{
    (void)node;
    (void)cursor;
    (void)generation;
    atomic_store(&picked, true);
    while (atomic_load(&hold) && !atomic_load(&finish))
        tick();
#if WN_CARRIER_OBSERVATION_ENABLED
    if (projection_error)
        return -1;
#endif
    const char *principal =
        "spiffe://wendy.sh/tenant/11111111-1111-4111-8111-111111111111/operator/Alice";
    struct wnt_record_view view = {.record = WendyComNetTopologyRecord_init_zero,
                                   .principal = principal,
                                   .principal_size = strlen(principal)};
    view.record.kind = 3;
    view.record.owner_role = WNT_TOPOLOGY_OPERATOR;
    view.record.owner_instance.size = 16;
    memset(view.record.owner_instance.bytes, 0xaa, 16);
    page->runtime_available = true;
    return wnt_record_copy(page, &view);
}
#if WN_CARRIER_OBSERVATION_ENABLED
static bool wncrypto_borrowed(const void *connection)
{
    return connection != NULL;
}
static bool wnrs_carrier_observation(const struct wnrs *s, int64_t now,
                                      struct wn_carrier_observation *row)
{
    *row = (struct wn_carrier_observation){.link = s->id, .selected_link = 1,
        .sampled_us = now, .origin = 7, .sequence = 8, .advertised = 0, .metric = 128,
        .candidate_expires_us = now + 1000000, .proof_expires_us = now + 2000000,
        .current_identity = true, .candidate = true, .authorized = true,
        .feasible = true, .twoway = true, .usable = true};
    return true;
}
static void *fixture_calloc(size_t count, size_t bytes)
{
    if (count == 1 && bytes == sizeof(struct wn_carrier_observations) &&
        atomic_load(&fail_observation_alloc)) {
        atomic_fetch_add(&rejected_observation_allocations, 1);
        return NULL;
    }
    return wendy_net_calloc(count, bytes);
}
static int fixture_printf(const char *format, ...)
{
    assert(task_id != (void *)1); /* Rendering never runs on the actor. */
    assert(!pthread_mutex_trylock(&state_lock));
    pthread_mutex_unlock(&state_lock);
    char rendered[640];
    va_list args;
    va_start(args, format);
    int size = vsnprintf(rendered, sizeof rendered, format, args);
    va_end(args);
    assert(size > 0 && (size_t)size < sizeof rendered);
    assert(strstr(rendered, "wn_carrier_observation "));
    if (strstr(rendered, "link=2 "))
        assert(strstr(rendered, "retiring=1 usable=0 "));
    atomic_fetch_add(&printed_rows, 1);
    atomic_store(&print_entered, true);
    while (atomic_load(&print_hold) && !atomic_load(&print_finish))
        tick();
    return size;
}
#define wendy_net_calloc fixture_calloc
#define printf fixture_printf
#endif
#include "topology_driver.inc"
#if WN_CARRIER_OBSERVATION_ENABLED
#undef printf
#undef wendy_net_calloc
#endif
static void *project(void *argument)
{
    task_id = (void *)1;
    service_topology_query(argument);
    return NULL;
}
struct read {
    WendyComNetTopologyParams params;
    WendyComNetTopologyPage page;
    WendyComResult result;
};
static void *read_page(void *argument)
{
    struct read *read = argument;
    read->result = wn_peer_topology(&read->params, &read->page);
    return NULL;
}
static void queued(void)
{
    for (unsigned i = 0; i < 1000; i++) {
        pthread_mutex_lock(&state_lock);
        bool ready = topology_query != NULL;
        pthread_mutex_unlock(&state_lock);
        if (ready)
            return;
        tick();
    }
    assert(!"caller did not submit its bounded query");
}
static void assert_empty(void)
{
    wendy_net_memory_snapshot_t memory;
    wendy_net_runtime_memory_snapshot(&memory);
    assert(!memory.current_bytes && !memory.allocation_count && !topology_query);
}
int main(void)
{
    struct read read = {0};
    /* OFF reads only identity/status: the closed ledger stays closed and empty. */
    assert(wn_peer_topology(&read.params, &read.page) == WendyComResult_WENDY_COM_RESULT_OK);
    assert_empty();
    assert(!atomic_load(&wakes));
    struct wnrs_node node = {0};
    struct peer_state root = {.router_node = &node};
#if WN_CARRIER_OBSERVATION_ENABLED
    /* The actor walks at most eight scalar rows, even with an oversized test
     * list. A retiring carrier cannot become usable through formatting. */
    struct peer_state extra[8] = {0};
    struct wnrs routes[9] = {0};
    struct peer_state *link = &root;
    for (unsigned i = 0; i < 9; i++) {
        routes[i].id = i + 1;
        link->router = &routes[i];
        link->attachment = 20 + i;
        link->active = i != 1;
        if (i < 8) {
            link->next = &extra[i];
            link = link->next;
        }
    }
    assert(sizeof(struct wn_carrier_observations) <= 1024);
#endif
    atomic_store(&state, &root);
    assert(wendy_net_runtime_memory_open());
    atomic_store(&topology_actor, (void *)1);
    task_id = (void *)1;
    assert(wn_peer_topology(&read.params, &read.page) == WendyComResult_WENDY_COM_RESULT_BUSY);
    task_id = (void *)2;
    assert_empty();
    /* Normal completion transfers exactly one selected row beyond actor lifetime. */
    pthread_t caller, actor;
    assert(!pthread_create(&caller, NULL, read_page, &read));
    queued();
    assert(!pthread_create(&actor, NULL, project, &root));
    pthread_join(actor, NULL);
    pthread_join(caller, NULL);
    assert(read.result == WendyComResult_WENDY_COM_RESULT_OK && read.page.has_record);
#if WN_CARRIER_OBSERVATION_ENABLED
    assert(atomic_load(&printed_rows) == WN_CARRIER_OBSERVATION_ROWS);
#endif
    wendy_net_runtime_memory_close();
    assert(!wendy_net_runtime_memory_drained());
    wnt_page_release(&read.page);
    assert(wendy_net_runtime_memory_drained());
    assert_empty();
    assert(wendy_net_runtime_memory_open());
#if WN_CARRIER_OBSERVATION_ENABLED
    /* Optional allocation pressure never changes the normal topology result. */
    read = (struct read){0};
    unsigned printed_before = atomic_load(&printed_rows);
    atomic_store(&fail_observation_alloc, true);
    assert(!pthread_create(&caller, NULL, read_page, &read));
    queued();
    assert(!pthread_create(&actor, NULL, project, &root));
    pthread_join(actor, NULL);
    pthread_join(caller, NULL);
    assert(read.result == WendyComResult_WENDY_COM_RESULT_OK && read.page.has_record);
    assert(atomic_load(&printed_rows) == printed_before);
    assert(atomic_load(&rejected_observation_allocations) == 1);
    atomic_store(&fail_observation_alloc, false);
    wnt_page_release(&read.page);
    assert_empty();
    /* Projection failure releases the optional scalar buffer without printing. */
    read = (struct read){0};
    projection_error = true;
    assert(!pthread_create(&caller, NULL, read_page, &read));
    queued();
    assert(!pthread_create(&actor, NULL, project, &root));
    pthread_join(actor, NULL);
    pthread_join(caller, NULL);
    assert(read.result == WendyComResult_WENDY_COM_RESULT_BUSY);
    assert(atomic_load(&printed_rows) == printed_before);
    projection_error = false;
    assert_empty();
    /* A blocked console owns flat scalars only. Another caller/actor round
     * trip finishes while the earlier renderer remains blocked. */
    read = (struct read){0};
    atomic_store(&print_hold, true);
    atomic_store(&print_finish, false);
    atomic_store(&print_entered, false);
    assert(!pthread_create(&caller, NULL, read_page, &read));
    queued();
    assert(!pthread_create(&actor, NULL, project, &root));
    pthread_join(actor, NULL);
    while (!atomic_load(&print_entered))
        tick();
    pthread_mutex_lock(&state_lock);
    assert(!topology_query);
    pthread_mutex_unlock(&state_lock);
    struct read next = {.params = {.cursor = 1}};
    pthread_t next_caller;
    assert(!pthread_create(&next_caller, NULL, read_page, &next));
    queued();
    assert(!pthread_create(&actor, NULL, project, &root));
    pthread_join(actor, NULL);
    pthread_join(next_caller, NULL);
    assert(next.result == WendyComResult_WENDY_COM_RESULT_OK && next.page.has_record);
    assert(!atomic_load(&print_finish));
    wnt_page_release(&next.page);
    atomic_store(&print_finish, true);
    pthread_join(caller, NULL);
    assert(read.result == WendyComResult_WENDY_COM_RESULT_OK);
    wnt_page_release(&read.page);
    atomic_store(&print_hold, false);
    assert_empty();
#endif
    /* Timeout before pickup removes both leases without an actor touching it. */
    read = (struct read){0};
    assert(wn_peer_topology(&read.params, &read.page) == WendyComResult_WENDY_COM_RESULT_BUSY);
    assert_empty();
    /* A timed-out caller cannot free a picked-up actor's immutable row owner. */
    read = (struct read){0};
    atomic_store(&hold, true);
    atomic_store(&finish, false);
    atomic_store(&picked, false);
    assert(!pthread_create(&caller, NULL, read_page, &read));
    queued();
    assert(!pthread_create(&actor, NULL, project, &root));
    while (!atomic_load(&picked))
        tick();
    pthread_join(caller, NULL);
    assert(read.result == WendyComResult_WENDY_COM_RESULT_BUSY);
    assert(topology_query);
    atomic_store(&finish, true);
    pthread_join(actor, NULL);
    assert_empty();
    /* OFF cancels queued work before waiting for management/context retirement. */
    read = (struct read){0};
    assert(!pthread_create(&caller, NULL, read_page, &read));
    queued();
    pthread_mutex_lock(&state_lock);
    wnqt_abort(&topology_query, wendy_net_free);
    pthread_mutex_unlock(&state_lock);
    pthread_join(caller, NULL);
    assert(read.result == WendyComResult_WENDY_COM_RESULT_BUSY);
    assert_empty();
    atomic_store(&state, NULL);
    wendy_net_runtime_memory_close();
    assert(wendy_net_runtime_memory_drained());
    printf(
        "PASS production topology caller/actor/OFF: fixed page=%zu mailbox=%zu, row lease drains ledger\n",
        sizeof read.page, sizeof(struct topology_query));
#if WN_CARRIER_OBSERVATION_ENABLED
    printf("local carrier observation: rows=%u scalar_row=%zu snapshot=%zu policy_state=0\n",
           WN_CARRIER_OBSERVATION_ROWS, sizeof(struct wn_carrier_observation),
           sizeof(struct wn_carrier_observations));
#endif
}
