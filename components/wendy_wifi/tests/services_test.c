#include <setjmp.h>
#include <stdio.h>
#include <stdarg.h>
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
static bool driver_model, driver_event_pending, access_point_up;
static bool cancel_retry_with_ip, cancel_retry_with_deinit;
static unsigned connect_calls, connect_failures, reconnect_waits, restore_after_waits;
static wifi_config_t last_config;
static char log_output[16384];

void test_log(const char *format, ...)
{
    size_t used = strlen(log_output);
    va_list args;
    va_start(args, format);
    vsnprintf(log_output + used, sizeof(log_output) - used, format, args);
    va_end(args);
}

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
    if (driver_model && driver_event_pending) {
        driver_event_pending = false;
        if (access_point_up) {
            ip_event_got_ip_t event = {0};
            wifi_event_handler(NULL, IP_EVENT, IP_EVENT_STA_GOT_IP, &event);
        } else {
            wifi_event_sta_disconnected_t event = {.reason = 201, .rssi = -60};
            wifi_event_handler(NULL, WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &event);
        }
    }
    if (notifications) {
        uint32_t pending = notifications;
        notifications = 0;
        return pending;
    }
    if (ticks == portMAX_DELAY) longjmp(worker_idle, 1);
    if (ticks == 10000) {
        assert(++reconnect_waits < 40);
        if (cancel_retry_with_deinit) {
            cancel_retry_with_deinit = false;
            wendy_wifi_deinit();
            return 1;
        }
        if (cancel_retry_with_ip) {
            cancel_retry_with_ip = false;
            ip_event_got_ip_t event = {0};
            wifi_event_handler(NULL, IP_EVENT, IP_EVENT_STA_GOT_IP, &event);
            return 1;
        }
        if (restore_after_waits && reconnect_waits >= restore_after_waits)
            access_point_up = true;
        return 0;
    }
    assert(ticks == 5000 && ++retry_waits < 10);
    if (disconnect_on_retry) {
        disconnect_on_retry = false;
        wifi_event_handler(NULL, WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, NULL);
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
    if (connect_failures) { connect_failures--; return ESP_ERR_NO_MEM; }
    if (driver_model) driver_event_pending = true;
    return ESP_OK;
}
esp_err_t esp_wifi_disconnect(void) { return ESP_OK; }
esp_err_t esp_wifi_set_mode(int mode) { return ESP_OK; }
esp_err_t esp_wifi_set_config(int interface, const wifi_config_t *config)
{
    last_config = *config;
    return ESP_OK;
}
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
    wendy_wifi_deinit();
    s_wifi_events = NULL;
    s_infra_initialized = s_connected = false;
    s_services_task = NULL;
    s_mdns_initialized = s_mdns_started = s_server_started = s_cloud_started = false;
    s_retry_count = 0;
    s_connect_requested = false;
    worker = NULL;
    event_bits = notifications = 0;
    task_creates = event_deletes = retry_waits = connect_wait_ms = 0;
    mdns_inits = hostname_sets = server_starts = cloud_starts = 0;
    mdns_failures = hostname_failures = cloud_failures = 0;
    fail_task = disconnect_on_retry = false;
    enrolled = true;
    driver_model = driver_event_pending = access_point_up = false;
    cancel_retry_with_ip = cancel_retry_with_deinit = false;
    connect_calls = connect_failures = reconnect_waits = restore_after_waits = 0;
    memset(&last_config, 0, sizeof(last_config));
    log_output[0] = 0;
}

static void got_ip(void)
{
    ip_event_got_ip_t event = {0};
    wifi_event_handler(NULL, IP_EVENT, IP_EVENT_STA_GOT_IP, &event);
}

static void run_worker_until_idle(void)
{
    assert(worker);
    if (!setjmp(worker_idle)) worker(NULL);
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

static void test_access_point_returns_after_outage(void)
{
    reset_test();
    assert(wifi_infra_init() == ESP_OK);
    driver_model = s_connect_requested = true;
    restore_after_waits = 30; // Five minutes beyond the initial retry burst.
    wifi_event_handler(NULL, WIFI_EVENT, WIFI_EVENT_STA_START, NULL);
    run_worker_until_idle();
    assert(s_connected && connect_calls == 36 && reconnect_waits == 30);
    assert(server_starts == 1 && cloud_starts == 1);
    assert(strstr(log_output, "reason=201 rssi=-60"));
}

static void test_lost_access_point_does_not_restart_services(void)
{
    reset_test();
    assert(wifi_infra_init() == ESP_OK);
    got_ip();
    run_worker_until_idle();
    driver_model = s_connect_requested = true;
    restore_after_waits = 2;
    wifi_event_sta_disconnected_t event = {.reason = 200, .rssi = -70};
    wifi_event_handler(NULL, WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &event);
    run_worker_until_idle();
    assert(s_connected && reconnect_waits == 2);
    assert(server_starts == 1 && cloud_starts == 1 && mdns_inits == 1);
}

static void test_refused_connect_request_retries(void)
{
    reset_test();
    assert(wifi_infra_init() == ESP_OK);
    driver_model = access_point_up = s_connect_requested = true;
    connect_failures = 2;
    wifi_event_handler(NULL, WIFI_EVENT, WIFI_EVENT_STA_START, NULL);
    run_worker_until_idle();
    assert(s_connected && connect_calls == 3 && reconnect_waits == 2);
}

static void test_pending_retry_cancellation(void)
{
    for (unsigned stop = 0; stop < 2; stop++) {
        reset_test();
        assert(wifi_infra_init() == ESP_OK);
        s_connect_requested = true;
        s_retry_count = WIFI_MAX_RETRIES;
        wifi_event_handler(NULL, WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, NULL);
        cancel_retry_with_ip = !stop;
        cancel_retry_with_deinit = stop;
        run_worker_until_idle();
        assert(connect_calls == 0 && reconnect_waits == 1);
        assert(s_connected == !stop);
    }
}

static void test_security_diagnostics_do_not_log_password(void)
{
    reset_test();
    assert(wifi_infra_init() == ESP_OK);
    assert(wifi_connect("test-network", "test-secret-never-log") != ESP_OK);
    assert(last_config.sta.sae_pwe_h2e == 0); // Preserve the existing SAE policy.
    assert(last_config.sta.threshold.authmode == WIFI_AUTH_WPA2_PSK);
    assert(!strstr(log_output, "test-secret-never-log"));
    wifi_event_sta_connected_t event = {.channel = 11, .authmode = 6};
    wifi_event_handler(NULL, WIFI_EVENT, WIFI_EVENT_STA_CONNECTED, &event);
    assert(strstr(log_output, "channel=11 authmode=6"));
}

int main(void)
{
    test_late_ip();
    test_startup_retry();
    test_disconnect_during_retry();
    test_unconfigured_and_worker_failure();
    test_access_point_returns_after_outage();
    test_lost_access_point_does_not_restart_services();
    test_refused_connect_request_retries();
    test_pending_retry_cancellation();
    test_security_diagnostics_do_not_log_password();
    puts("WiFi startup, recovery, cancellation and security diagnostic tests passed");
    return 0;
}
