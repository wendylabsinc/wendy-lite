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
static unsigned netif_inits, event_loop_inits, station_netifs, driver_inits, credential_opens;
static unsigned mdns_inits, hostname_sets, server_starts, cloud_starts;
static unsigned mdns_failures, hostname_failures, cloud_failures;
static bool fail_task, enrolled, disconnect_on_retry;
static bool driver_model, driver_event_pending, access_point_up;
static bool driver_started, driver_start_pending;
static bool driver_connected, driver_disconnect_pending, timeout_with_connect_pending;
static bool drop_control_marker;
static unsigned control_posts, control_post_failures, control_ack_timeouts, control_waits;
static unsigned stop_failures, config_failures;
static int32_t delayed_control_id, latest_control_id, delivered_control_id, queued_control_id;
static bool replay_stale_control, deinit_on_control_wait, replace_on_control_wait;
static TickType_t test_ticks;
static TickType_t stale_ack_elapsed, last_control_wait_ticks;
static unsigned driver_starts, station_start_events, credential_saves;
static const char *access_point_ssid, *conf_ssid, *conf_password;
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

static void deliver_station_start(void)
{
    if (!driver_start_pending) return;
    driver_start_pending = false;
    station_start_events++;
    wifi_event_handler(NULL, WIFI_EVENT, WIFI_EVENT_STA_START, NULL);
}

static void deliver_driver_event(void)
{
    driver_event_pending = false;
    if (access_point_up && (!access_point_ssid ||
        !strcmp((const char *)last_config.sta.ssid, access_point_ssid))) {
        driver_connected = true;
        ip_event_got_ip_t event = {0};
        wifi_event_handler(NULL, IP_EVENT, IP_EVENT_STA_GOT_IP, &event);
    } else {
        wifi_event_sta_disconnected_t event = {.reason = 201, .rssi = -60};
        wifi_event_handler(NULL, WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &event);
    }
}

static void deliver_control(int32_t id)
{
    delivered_control_id = id;
    wifi_event_handler(NULL, WENDY_WIFI_CONTROL_EVENT, id, NULL);
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
    if (bits == BIT2) {
        control_waits++;
        last_control_wait_ticks = ticks;
        if (deinit_on_control_wait) {
            deinit_on_control_wait = false;
            wendy_wifi_deinit();
        }
        if (replace_on_control_wait) {
            replace_on_control_wait = false;
            assert(wendy_wifi_try_connect("replacement-network", "replacement-password") == ESP_OK);
            deliver_control(delayed_control_id);
        }
        if (!(event_bits & bits) && queued_control_id >= 0) {
            int32_t id = queued_control_id;
            queued_control_id = -1;
            deliver_control(id);
        }
        EventBits_t result = event_bits & bits;
        if (result && queued_control_id >= 0) test_ticks += stale_ack_elapsed;
        if (clear) event_bits &= ~bits;
        if (!result) test_ticks += ticks;
        return result;
    }
    connect_wait_ms = ticks;
    deliver_station_start();
    if (timeout_with_connect_pending) {
        timeout_with_connect_pending = false;
        assert(driver_event_pending);
        return 0;
    }
    unsigned events = 0;
    while (driver_model && driver_event_pending && !(event_bits & bits)) {
        assert(++events <= WIFI_MAX_RETRIES + 1);
        deliver_driver_event();
    }
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
    deliver_station_start();
    if (driver_model && driver_event_pending) deliver_driver_event();
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
TickType_t xTaskGetTickCount(void) { return test_ticks; }
esp_err_t esp_event_loop_create_default(void) { event_loop_inits++; return ESP_OK; }
esp_err_t esp_event_handler_instance_register(esp_event_base_t base, int32_t id,
    void (*handler)(void *, esp_event_base_t, int32_t, void *), void *arg,
    esp_event_handler_instance_t *instance) { return ESP_OK; }
esp_err_t esp_event_post(esp_event_base_t base, int32_t id, const void *data, size_t size, TickType_t ticks)
{
    control_posts++;
    if (control_post_failures) {
        control_post_failures--;
        return ESP_ERR_TIMEOUT;
    }
    latest_control_id = id;
    // Driver events already queued by stop must precede the control marker.
    deliver_station_start();
    if (driver_disconnect_pending) {
        driver_disconnect_pending = false;
        unsigned before = connect_calls;
        wifi_event_handler(NULL, WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, NULL);
        assert(connect_calls == before);
    }
    if (control_ack_timeouts) {
        control_ack_timeouts--;
        delayed_control_id = id;
    } else if (replay_stale_control) {
        replay_stale_control = false;
        deliver_control(delayed_control_id);
        queued_control_id = id;
    } else if (!drop_control_marker) {
        deliver_control(id);
    }
    return ESP_OK;
}
esp_err_t esp_netif_init(void) { netif_inits++; return ESP_OK; }
void *esp_netif_create_default_wifi_sta(void) { station_netifs++; return &event_bits; }
esp_err_t esp_wifi_init(const wifi_init_config_t *config) { driver_inits++; return ESP_OK; }
esp_err_t esp_wifi_connect(void)
{
    if (driver_model) assert(driver_started);
    connect_calls++;
    if (connect_failures) { connect_failures--; return ESP_ERR_NO_MEM; }
    if (driver_model) driver_event_pending = true;
    return ESP_OK;
}
esp_err_t esp_wifi_disconnect(void) { return ESP_OK; }
esp_err_t esp_wifi_set_mode(int mode) { return ESP_OK; }
esp_err_t esp_wifi_set_config(int interface, const wifi_config_t *config)
{
    assert(delivered_control_id == latest_control_id && queued_control_id < 0);
    if (config_failures) { config_failures--; return ESP_ERR_NO_MEM; }
    if (driver_model && (driver_event_pending || driver_connected)) return ESP_ERR_WIFI_STATE;
    last_config = *config;
    return ESP_OK;
}
esp_err_t esp_wifi_start(void)
{
    driver_starts++;
    if (!driver_started) {
        driver_started = true;
        if (driver_model) driver_start_pending = true;
    }
    return ESP_OK;
}
esp_err_t esp_wifi_stop(void)
{
    if (stop_failures) { stop_failures--; return ESP_ERR_NO_MEM; }
    driver_disconnect_pending |= driver_event_pending || driver_connected;
    driver_connected = false;
    driver_started = driver_event_pending = false;
    return ESP_OK;
}
esp_err_t esp_wifi_deinit(void) { return ESP_OK; }
esp_err_t nvs_open(const char *name, int mode, nvs_handle_t *handle) { credential_opens++; *handle = 1; return ESP_OK; }
esp_err_t nvs_get_str(nvs_handle_t handle, const char *name, char *out, size_t *size)
{
    strlcpy(out, !strcmp(name, "ssid") ? "test-network" : "", *size);
    return ESP_OK;
}
esp_err_t nvs_set_str(nvs_handle_t handle, const char *name, const char *value) { return ESP_OK; }
esp_err_t nvs_commit(nvs_handle_t handle) { credential_saves++; return ESP_OK; }
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
struct wendy_conf_span wendy_conf_get_network_ssid(void)
{
    return (struct wendy_conf_span){(const uint8_t *)conf_ssid, strlen(conf_ssid)};
}
struct wendy_conf_span wendy_conf_get_network_password(void)
{
    return (struct wendy_conf_span){(const uint8_t *)conf_password, strlen(conf_password)};
}
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
    driver_started = driver_start_pending = false;
    driver_connected = driver_disconnect_pending = timeout_with_connect_pending = false;
    drop_control_marker = false;
    control_posts = control_post_failures = control_ack_timeouts = control_waits = 0;
    stop_failures = config_failures = 0;
    delayed_control_id = latest_control_id = delivered_control_id = queued_control_id = -1;
    replay_stale_control = deinit_on_control_wait = replace_on_control_wait = false;
    test_ticks = 0;
    stale_ack_elapsed = last_control_wait_ticks = 0;
    driver_starts = station_start_events = credential_saves = 0;
    access_point_ssid = NULL;
    conf_ssid = conf_password = "";
    cancel_retry_with_ip = cancel_retry_with_deinit = false;
    connect_calls = connect_failures = reconnect_waits = restore_after_waits = 0;
    memset(&last_config, 0, sizeof(last_config));
    log_output[0] = 0;
}

static void got_ip(void)
{
    s_connect_requested = true;
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
    driver_model = true;
    restore_after_waits = 30; // Five minutes beyond the initial retry burst.
    assert(wifi_connect("test-network", "") != ESP_OK);
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
    driver_model = driver_started = s_connect_requested = true;
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
    driver_model = access_point_up = true;
    connect_failures = 2;
    assert(wifi_connect("test-network", "") != ESP_OK);
    run_worker_until_idle();
    assert(s_connected && connect_calls == 3 && reconnect_waits == 2);
}

static void test_credential_fallback_connects_on_started_station(void)
{
    for (unsigned failure = 0; failure < 3; failure++) {
        reset_test();
        driver_model = access_point_up = true;
        access_point_ssid = conf_ssid = "reachable-fallback";
        conf_password = "fallback-password";
        connect_failures = failure == 1;
        timeout_with_connect_pending = failure == 2;

        // The NVS request exhausts its retries, is refused, or remains in
        // flight when the synchronous wait expires (observed on ESP32-C5).
        assert(wendy_wifi_init() == ESP_OK);
        assert(wendy_wifi_is_connected());
        assert(driver_starts == 2 && station_start_events == 2);
        assert(connect_calls == (failure ? 2 : 7));
        assert(!strcmp((const char *)last_config.sta.ssid, conf_ssid));
        assert(!strcmp((const char *)last_config.sta.password, conf_password));
        assert(!mdns_inits && !server_starts && !cloud_starts);
        run_worker_until_idle();
        assert(!reconnect_waits && connect_calls == (failure ? 2 : 7));
        assert(mdns_inits == 1 && server_starts == 1 && cloud_starts == 1);
    }
}

static void test_new_credentials_after_failed_connection(void)
{
    reset_test();
    driver_model = access_point_up = true;
    access_point_ssid = "reachable-network";
    assert(wendy_wifi_init() != ESP_OK);
    assert(!wendy_wifi_is_connected() && connect_calls == 6);

    assert(wendy_wifi_try_connect(access_point_ssid, "new-password") == ESP_OK);
    assert(wendy_wifi_is_connected() && credential_saves == 1);
    assert(driver_starts == 2 && station_start_events == 2 && connect_calls == 7);
    run_worker_until_idle();
    assert(!reconnect_waits && connect_calls == 7);
    assert(server_starts == 1 && cloud_starts == 1);

    // Replacing an established connection stops and starts the radio without
    // a duplicate connection request from the new STA_START event.
    access_point_ssid = "replacement-network";
    assert(wendy_wifi_try_connect(access_point_ssid, "replacement-password") == ESP_OK);
    assert(wendy_wifi_is_connected() && credential_saves == 2);
    assert(driver_starts == 3 && station_start_events == 3 && connect_calls == 8);
    run_worker_until_idle();
    assert(!reconnect_waits && connect_calls == 8);
    assert(server_starts == 1 && cloud_starts == 1);
}

static void test_handoff_timeout_and_stale_ip(void)
{
    reset_test();
    assert(wifi_infra_init() == ESP_OK);
    drop_control_marker = true;
    assert(wifi_connect("test-network", "") == ESP_ERR_TIMEOUT);
    assert(!connect_calls && !driver_starts && !s_connect_requested);

    reset_test();
    assert(wifi_infra_init() == ESP_OK);
    got_ip();
    wendy_wifi_deinit();
    ip_event_got_ip_t event = {0};
    wifi_event_handler(NULL, IP_EVENT, IP_EVENT_STA_GOT_IP, &event);
    run_worker_until_idle();
    assert(!wendy_wifi_is_connected() && !server_starts && !cloud_starts);
}

static void test_handoff_recovers_after_event_loop_stall(void)
{
    reset_test();
    driver_model = access_point_up = true;
    char ssid[] = "test-network", password[] = "retry-password";
    control_ack_timeouts = 1;
    assert(wendy_wifi_try_connect(ssid, password) == ESP_ERR_TIMEOUT);
    assert(!driver_starts && !connect_calls);
    memset(ssid, 'x', sizeof(ssid) - 1);
    memset(password, 'x', sizeof(password) - 1);
    // The event loop resumes after the caller has already received its error.
    deliver_control(delayed_control_id);
    run_worker_until_idle();
    assert(wendy_wifi_is_connected() && reconnect_waits == 1 && control_posts == 2);
    assert(!strcmp((const char *)last_config.sta.ssid, "test-network"));
    assert(!strcmp((const char *)last_config.sta.password, "retry-password"));
    assert(connect_calls == 1 && server_starts == 1 && cloud_starts == 1);
    assert(strstr(log_output, "WiFi handoff event drain failed"));
    assert(!strstr(log_output, "retry-password"));
}

static void test_handoff_retries_resource_failures(void)
{
    for (unsigned failure = 0; failure < 3; failure++) {
        reset_test();
        driver_model = access_point_up = true;
        if (failure == 0) control_post_failures = 2;
        if (failure == 1) stop_failures = 2;
        if (failure == 2) config_failures = 2;
        esp_err_t expected = failure == 0 ? ESP_ERR_TIMEOUT : ESP_ERR_NO_MEM;
        assert(wendy_wifi_try_connect("test-network", "test-password") == expected);
        assert(!driver_starts && !connect_calls);
        run_worker_until_idle();
        assert(wendy_wifi_is_connected() && reconnect_waits == 2);
        assert(driver_starts == 1 && connect_calls == 1);
    }
}

static void test_stale_ack_does_not_complete_next_drain(void)
{
    reset_test();
    driver_model = access_point_up = true;
    control_ack_timeouts = 1;
    assert(wendy_wifi_try_connect("test-network", "test-password") == ESP_ERR_TIMEOUT);
    int32_t expired = delayed_control_id;
    replay_stale_control = true;
    stale_ack_elapsed = 2000;
    test_ticks = UINT32_MAX - 1000; // Exercise tick wrap during the drain wait.
    // The next wait wakes for the old marker first. Configuration must wait
    // for the new marker, without restarting its five-second deadline.
    run_worker_until_idle();
    assert(wendy_wifi_is_connected() && latest_control_id != expired);
    assert(control_posts == 2 && control_waits == 3 && reconnect_waits == 1);
    assert(last_control_wait_ticks == 3000);
    assert(connect_calls == 1);
}

static void test_new_request_cancels_handoff_recovery(void)
{
    reset_test();
    driver_model = access_point_up = true;
    control_ack_timeouts = 1;
    assert(wendy_wifi_try_connect("obsolete-network", "obsolete-password") == ESP_ERR_TIMEOUT);
    int32_t expired = delayed_control_id;
    assert(wendy_wifi_try_connect("replacement-network", "replacement-password") == ESP_OK);
    deliver_control(expired);
    run_worker_until_idle();
    assert(wendy_wifi_is_connected() && control_posts == 2 && connect_calls == 1);
    assert(!reconnect_waits && credential_saves == 1);
    assert(!strcmp((const char *)last_config.sta.ssid, "replacement-network"));

    // Also supersede a request while its drain is still waiting.
    reset_test();
    driver_model = access_point_up = true;
    control_ack_timeouts = 1;
    replace_on_control_wait = true;
    assert(wendy_wifi_try_connect("obsolete-network", "obsolete-password") == ESP_ERR_INVALID_STATE);
    run_worker_until_idle();
    assert(wendy_wifi_is_connected() && control_posts == 2 && connect_calls == 1);
    assert(!reconnect_waits && credential_saves == 1);
    assert(!strcmp((const char *)last_config.sta.ssid, "replacement-network"));
}

static void test_shutdown_cancels_handoff_recovery(void)
{
    for (unsigned during_wait = 0; during_wait < 2; during_wait++) {
        reset_test();
        driver_model = access_point_up = true;
        control_ack_timeouts = 2;
        assert(wendy_wifi_try_connect("test-network", "test-password") == ESP_ERR_TIMEOUT);
        if (during_wait) {
            deinit_on_control_wait = true;
        } else {
            wendy_wifi_deinit();
            deliver_control(delayed_control_id);
        }
        run_worker_until_idle();
        assert(!wendy_wifi_is_connected() && !connect_calls && !driver_starts);
        assert(control_posts == 1 + during_wait && reconnect_waits == during_wait);
        assert(!server_starts && !cloud_starts);
    }
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
    test_credential_fallback_connects_on_started_station();
    test_new_credentials_after_failed_connection();
    test_handoff_timeout_and_stale_ip();
    test_handoff_recovers_after_event_loop_stall();
    test_handoff_retries_resource_failures();
    test_stale_ack_does_not_complete_next_drain();
    test_new_request_cancels_handoff_recovery();
    test_shutdown_cancels_handoff_recovery();
    test_pending_retry_cancellation();
    test_security_diagnostics_do_not_log_password();
    puts("WiFi startup, recovery, cancellation and security diagnostic tests passed");
    return 0;
}
