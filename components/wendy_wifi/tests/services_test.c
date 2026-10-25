#include <setjmp.h>
#include <stdio.h>
#include <string.h>
#include "../src/wendy_wifi.c"

const char wifi_event_base[] = "wifi", ip_event_base[] = "ip";
static jmp_buf worker_idle;
static void (*worker)(void *);
static EventBits_t event_bits;
static uint32_t notifications;
static unsigned task_creates, event_deletes, retry_waits, connect_wait_ms;
static unsigned mdns_inits, hostname_sets, server_starts, cloud_starts;
static unsigned mdns_failures, hostname_failures, cloud_failures;
static bool fail_task, enrolled, disconnect_on_retry;
// Radio model: esp_wifi_connect() reports its result later, as the driver does.
static unsigned connect_calls, reconnect_waits, refused_connects;
static bool connect_in_flight, access_point_up;

const char *esp_err_to_name(esp_err_t error) { return "injected failure"; }
EventGroupHandle_t xEventGroupCreate(void) { return &event_bits; }
void vEventGroupDelete(EventGroupHandle_t group) { event_deletes++; }
EventBits_t xEventGroupClearBits(EventGroupHandle_t group, EventBits_t bits)
{
    event_bits &= ~bits;
    return event_bits;
}
EventBits_t xEventGroupSetBits(EventGroupHandle_t group, EventBits_t bits)
{
    event_bits |= bits;
    return event_bits;
}
EventBits_t xEventGroupWaitBits(EventGroupHandle_t group, EventBits_t bits,
                               int clear, int all, TickType_t ticks)
{
    connect_wait_ms = ticks;
    return event_bits & bits;
}
int xTaskCreate(void (*task)(void *), const char *name, unsigned stack,
                void *arg, unsigned priority, TaskHandle_t *handle)
{
    task_creates++;
    if (fail_task) return 0;
    worker = task;
    *handle = &event_bits;
    return pdPASS;
}
void xTaskNotifyGive(TaskHandle_t task)
{
    assert(task == &event_bits);
    notifications++;
}
uint32_t ulTaskNotifyTake(int clear, TickType_t ticks)
{
    assert(clear == pdTRUE);
    if (notifications) {
        uint32_t pending = notifications;
        notifications = 0;
        return pending;
    }
    if (ticks == portMAX_DELAY) longjmp(worker_idle, 1);
    if (ticks == pdMS_TO_TICKS(WIFI_RECONNECT_INTERVAL_MS)) {
        // The reconnect interval elapses with no WiFi event.
        assert(++reconnect_waits < 1000);
        return 0;
    }
    assert(ticks == 5000 && ++retry_waits < 10);
    if (disconnect_on_retry) {
        disconnect_on_retry = false;
        wifi_event_sta_disconnected_t event = { .reason = WIFI_REASON_BEACON_TIMEOUT };
        wifi_event_handler(NULL, WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &event);
    }
    return 0;
}
void vTaskDelay(TickType_t ticks) {}
esp_err_t esp_event_loop_create_default(void) { return ESP_OK; }
esp_err_t esp_event_handler_instance_register(esp_event_base_t base, int32_t id,
    void (*handler)(void *, esp_event_base_t, int32_t, void *), void *arg,
    esp_event_handler_instance_t *instance) { return ESP_OK; }
esp_err_t esp_netif_init(void) { return ESP_OK; }
void *esp_netif_create_default_wifi_sta(void) { return &event_bits; }
esp_err_t esp_wifi_init(const wifi_init_config_t *config) { return ESP_OK; }
esp_err_t esp_wifi_connect(void)
{
    connect_calls++;
    if (refused_connects) { refused_connects--; return ESP_FAIL; }
    connect_in_flight = true;
    return ESP_OK;
}
esp_err_t esp_wifi_disconnect(void) { return ESP_OK; }
esp_err_t esp_wifi_set_mode(int mode) { return ESP_OK; }
esp_err_t esp_wifi_set_config(int interface, const wifi_config_t *config) { return ESP_OK; }
esp_err_t esp_wifi_start(void) { return ESP_OK; }
esp_err_t esp_wifi_stop(void) { return ESP_OK; }
esp_err_t esp_wifi_deinit(void) { return ESP_OK; }
esp_err_t nvs_open(const char *name, int mode, nvs_handle_t *handle) { *handle = 1; return ESP_OK; }
esp_err_t nvs_get_str(nvs_handle_t handle, const char *name, char *out, size_t *size)
{
    strlcpy(out, !strcmp(name, "ssid") ? "test-network" : "", *size);
    return ESP_OK;
}
esp_err_t nvs_set_str(nvs_handle_t handle, const char *name, const char *value) { return ESP_OK; }
esp_err_t nvs_commit(nvs_handle_t handle) { return ESP_OK; }
void nvs_close(nvs_handle_t handle) {}
esp_err_t mdns_init(void)
{
    mdns_inits++;
    if (mdns_failures) { mdns_failures--; return ESP_ERR_NO_MEM; }
    return ESP_OK;
}
esp_err_t mdns_hostname_set(const char *hostname)
{
    assert(!strcmp(hostname, "wendylt-test-board"));
    hostname_sets++;
    if (hostname_failures) { hostname_failures--; return ESP_FAIL; }
    return ESP_OK;
}
void mdns_free(void) {}
void wendy_server_start(void) { server_starts++; }
esp_err_t wendy_cloud_start(void)
{
    assert(enrolled);
    cloud_starts++;
    if (cloud_failures) { cloud_failures--; return ESP_ERR_NO_MEM; }
    return ESP_OK;
}
const char *wendy_conf_get_resolved_device_name(void) { return "test-board"; }
struct wendy_conf_span wendy_conf_get_network_ssid(void) { return (struct wendy_conf_span){0}; }
struct wendy_conf_span wendy_conf_get_network_password(void) { return (struct wendy_conf_span){0}; }
bool wendy_conf_has_enrollment(void) { return enrolled; }
size_t strlcpy(char *dest, const char *source, size_t size)
{
    size_t n = strlen(source);
    if (size) { size_t copy = n < size - 1 ? n : size - 1; memcpy(dest, source, copy); dest[copy] = 0; }
    return n;
}

static void reset_test(void)
{
    s_wifi_events = NULL;
    s_infra_initialized = s_connected = false;
    s_services_task = NULL;
    s_mdns_initialized = s_mdns_started = s_server_started = s_cloud_started = false;
    s_retry_count = 0;
    s_connect_requested = false;
    s_reconnect_pending = false;
    worker = NULL;
    event_bits = notifications = 0;
    task_creates = event_deletes = retry_waits = connect_wait_ms = 0;
    mdns_inits = hostname_sets = server_starts = cloud_starts = 0;
    mdns_failures = hostname_failures = cloud_failures = 0;
    fail_task = disconnect_on_retry = false;
    enrolled = true;
    connect_calls = reconnect_waits = refused_connects = 0;
    connect_in_flight = false;
    access_point_up = true;
}

static void got_ip(void)
{
    ip_event_got_ip_t event = {0};
    wifi_event_handler(NULL, IP_EVENT, IP_EVENT_STA_GOT_IP, &event);
}

static void disconnected(uint8_t reason)
{
    wifi_event_sta_disconnected_t event = { .reason = reason };
    wifi_event_handler(NULL, WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &event);
}

static void run_worker_until_idle(void)
{
    assert(worker);
    if (!setjmp(worker_idle)) worker(NULL);
}

// Delivers the driver's result for an outstanding esp_wifi_connect(), then
// lets the worker run. Returns false once nothing is in flight.
static bool radio_step(void)
{
    if (!connect_in_flight) return false;
    connect_in_flight = false;
    if (access_point_up) got_ip();
    else disconnected(WIFI_REASON_NO_AP_FOUND);
    run_worker_until_idle();
    return true;
}

// Runs the radio for up to `ms` of reconnect intervals.
static void run_radio_for(unsigned ms)
{
    unsigned waits = reconnect_waits + ms / WIFI_RECONNECT_INTERVAL_MS;
    for (unsigned steps = 0; steps < 1000 && reconnect_waits < waits; steps++)
        if (!radio_step()) break;
}

static void test_late_ip(void)
{
    reset_test();
    // Stored credentials exist, but the initial 30-second DHCP wait expires.
    assert(wendy_wifi_init() != ESP_OK);
    assert(connect_wait_ms == 30000 && !wendy_wifi_is_connected());
    assert(task_creates == 1 && !mdns_inits && !cloud_starts);
    got_ip();
    assert(wendy_wifi_is_connected());
    // The event handler schedules work; it must not start services itself.
    assert(!mdns_inits && !server_starts && !cloud_starts);
    run_worker_until_idle();
    assert(mdns_inits == 1 && hostname_sets == 1 && server_starts == 1 && cloud_starts == 1);
    got_ip(); got_ip();
    run_worker_until_idle();
    assert(task_creates == 1 && mdns_inits == 1 && server_starts == 1 && cloud_starts == 1);
}

static void test_startup_retry(void)
{
    reset_test();
    assert(wifi_infra_init() == ESP_OK);
    mdns_failures = cloud_failures = 1;
    got_ip();
    run_worker_until_idle();
    assert(retry_waits == 1 && mdns_inits == 2 && cloud_starts == 2);
    assert(server_starts == 1 && hostname_sets == 1);

    reset_test();
    assert(wifi_infra_init() == ESP_OK);
    hostname_failures = 1;
    got_ip();
    run_worker_until_idle();
    assert(retry_waits == 1 && mdns_inits == 1 && hostname_sets == 2);
    assert(server_starts == 1 && cloud_starts == 1);
}

static void test_disconnect_during_retry(void)
{
    reset_test();
    assert(wifi_infra_init() == ESP_OK);
    cloud_failures = 2;
    disconnect_on_retry = true;
    got_ip();
    run_worker_until_idle();
    assert(!wendy_wifi_is_connected() && !(event_bits & WIFI_CONNECTED_BIT));
    assert(cloud_starts == 1);
    cloud_failures = 0;
    got_ip();
    run_worker_until_idle();
    assert(cloud_starts == 2 && server_starts == 1 && mdns_inits == 1);
}

static void test_unconfigured_and_worker_failure(void)
{
    reset_test();
    fail_task = true;
    assert(wifi_infra_init() == ESP_ERR_NO_MEM && event_deletes == 1 && !s_wifi_events);
    fail_task = false;
    assert(wifi_infra_init() == ESP_OK);
    enrolled = false;
    got_ip();
    run_worker_until_idle();
    assert(server_starts == 1 && cloud_starts == 0 && retry_waits == 0);
    enrolled = true;
    got_ip();
    run_worker_until_idle();
    assert(server_starts == 1 && cloud_starts == 1);
}

// The access point disappears for minutes while the board is serving, as when
// a phone hotspot is switched off, and then comes back.
static void test_access_point_outage(void)
{
    reset_test();
    assert(wendy_wifi_init() != ESP_OK);
    wifi_event_handler(NULL, WIFI_EVENT, WIFI_EVENT_STA_START, NULL);
    assert(radio_step() && wendy_wifi_is_connected());
    assert(server_starts == 1 && cloud_starts == 1);

    access_point_up = false;
    disconnected(WIFI_REASON_BEACON_TIMEOUT);
    run_radio_for(5 * 60 * 1000);
    // The station keeps trying for the whole outage.
    assert(reconnect_waits == 5 * 60 * 1000 / WIFI_RECONNECT_INTERVAL_MS);
    assert(!wendy_wifi_is_connected() && (event_bits & WIFI_FAIL_BIT));
    // After the fast retries, each attempt waits one full interval.
    assert(connect_calls == 1 + WIFI_MAX_RETRIES + reconnect_waits);

    access_point_up = true;
    assert(radio_step() && wendy_wifi_is_connected());
    assert(mdns_inits == 1 && server_starts == 1 && cloud_starts == 1);
    // A later drop starts with fast retries again.
    unsigned calls = connect_calls;
    disconnected(WIFI_REASON_BEACON_TIMEOUT);
    assert(connect_calls == calls + 1 && s_retry_count == 1);
}

// The access point is off when the board powers up.
static void test_access_point_absent_at_boot(void)
{
    reset_test();
    access_point_up = false;
    assert(wendy_wifi_init() != ESP_OK);
    wifi_event_handler(NULL, WIFI_EVENT, WIFI_EVENT_STA_START, NULL);
    run_radio_for(60 * 1000);
    assert(reconnect_waits == 60 * 1000 / WIFI_RECONNECT_INTERVAL_MS);
    assert(!mdns_inits && !server_starts && !cloud_starts);

    access_point_up = true;
    assert(radio_step() && wendy_wifi_is_connected());
    assert(mdns_inits == 1 && server_starts == 1 && cloud_starts == 1);
}

// An address that arrives before the interval elapses, e.g. after new
// credentials were provisioned, cancels the slow retry. Otherwise it would
// fire during the fast retries of the next drop.
static void test_connection_cancels_pending_retry(void)
{
    reset_test();
    assert(wendy_wifi_init() != ESP_OK);
    for (int i = 0; i <= WIFI_MAX_RETRIES; i++) disconnected(WIFI_REASON_NO_AP_FOUND);
    assert(s_reconnect_pending && connect_calls == WIFI_MAX_RETRIES);
    got_ip();
    run_worker_until_idle();
    assert(wendy_wifi_is_connected() && server_starts == 1 && !reconnect_waits);

    disconnected(WIFI_REASON_BEACON_TIMEOUT);
    run_worker_until_idle();
    assert(connect_calls == WIFI_MAX_RETRIES + 1 && !reconnect_waits);
}

// A refused attempt produces no WiFi event, so the worker must schedule the
// next one itself. Deinitialization stops the attempts.
static void test_refused_reconnect_and_deinit(void)
{
    reset_test();
    access_point_up = false;
    assert(wendy_wifi_init() != ESP_OK);
    wifi_event_handler(NULL, WIFI_EVENT, WIFI_EVENT_STA_START, NULL);
    for (int i = 0; i < WIFI_MAX_RETRIES; i++) assert(radio_step());
    assert(connect_calls == 1 + WIFI_MAX_RETRIES && !reconnect_waits);
    refused_connects = 1;
    assert(radio_step());
    assert(reconnect_waits == 2 && connect_calls == 3 + WIFI_MAX_RETRIES && connect_in_flight);

    wendy_wifi_deinit();
    run_worker_until_idle();
    assert(radio_step() && !connect_in_flight);
    assert(reconnect_waits == 2 && connect_calls == 3 + WIFI_MAX_RETRIES);
}

int main(void)
{
    test_late_ip();
    test_startup_retry();
    test_disconnect_during_retry();
    test_unconfigured_and_worker_failure();
    test_access_point_outage();
    test_access_point_absent_at_boot();
    test_connection_cancels_pending_retry();
    test_refused_reconnect_and_deinit();
    puts("late WiFi IP, service retry and reconnection tests passed");
    return 0;
}
