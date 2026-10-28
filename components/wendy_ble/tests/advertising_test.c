#ifndef CONFIG_WENDY_BLE_SETUP
#define CONFIG_WENDY_BLE_SETUP 0
#endif
// Compile the transport itself so startup, GATT and restart regressions exercise
// the firmware code. No scheduler or radio runs in these host tests.
#include "../src/wendy_ble.c"

#include <stdio.h>

bool test_enrolled, test_reset, test_current, test_nimble_initialized;
bool test_installed, test_challenge_fails;
char test_enrollment_device_id[65];
unsigned test_adv_starts;
unsigned test_random_addresses;
bool test_fail_random_address;
uint8_t test_adv_address_type;
bool test_fail_semaphore, test_fail_task;
unsigned test_semaphore_calls, test_semaphores_allocated, test_semaphores_deleted;
unsigned test_task_calls, test_tasks_created, test_task_stack;
struct test_hs_cfg ble_hs_cfg;
struct ble_hs_adv_fields test_adv, test_rsp;
const struct ble_gatt_svc_def *test_services;

static bool test_physical_claim, test_mesh_claim;
bool wble_l2cap_connection_idle(uint16_t handle){(void)handle;return !test_physical_claim;}
bool wble_mesh_uses_connection(uint16_t handle){(void)handle;return test_mesh_claim;}
static uint16_t test_psm;
esp_err_t wble_l2cap_init(uint16_t psm) { test_psm = psm; return ESP_OK; }
void wble_setup_session(void) {}
bool wble_l2cap_wait_session(TickType_t timeout) { return false; }
void wble_l2cap_end_session(bool disconnect_peer) {}
void wble_l2cap_peer_disconnected(uint16_t handle) {}
int wble_l2cap_wakeup_fd(void) { return -1; }
bool wble_l2cap_can_read(void) { return false; }
static bool test_l2cap_writable;
bool wble_l2cap_can_write(void) { return test_l2cap_writable; }
static esp_err_t test_handshake_result;
static unsigned test_handshake_calls;
esp_err_t wble_tls_session_start(bool enrolled) {
#if WENDY_BLE_IO_DISPATCH_TEST
    extern void test_physical_tls_entry(void);
    test_physical_tls_entry();
#endif
    ++test_handshake_calls; return test_handshake_result;
}
void wble_tls_session_end(void) {}
ssize_t wble_tls_read(void *buf, size_t len) { return WBLE_ERR_WANT_READ; }
ssize_t wble_tls_write(const void *buf, size_t len) { return WBLE_ERR_WANT_WRITE; }
bool wble_tls_pending(void) { return false; }

static void reset_fixture(void)
{
    free(_device_id);
    free(_device_name);
    free(_display_name);
    _device_id = _device_name = _display_name = NULL;
    _principal[0] = 0;
    _host_initialized = _started = _enrolled = _setup = false;
    _setup_address_ready = false;
    _own_addr_type = 0;
    test_random_addresses = 0;
    test_fail_random_address = false;
    test_nimble_initialized = false;
    if (_link_closed)
        vSemaphoreDelete(_link_closed);
    _link_closed = NULL;
    assert(test_semaphores_allocated == test_semaphores_deleted);
    _mfg_data_len = 0;
    test_enrolled = test_reset = test_installed = test_challenge_fails = false;
    test_current = true;
    strcpy(test_enrollment_device_id, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
    test_adv_starts = 0;
    test_advertising_active=false;test_advertising_error=0;
    test_fail_semaphore = test_fail_task = false;
    test_semaphore_calls = test_semaphores_allocated = test_semaphores_deleted = 0;
    test_task_calls = test_tasks_created = test_task_stack = 0;
    test_adv = (struct ble_hs_adv_fields){0};
    test_rsp = (struct ble_hs_adv_fields){0};
    test_services = NULL;
}

#if CONFIG_WENDY_PKI || !CONFIG_WENDY_BLE_REQUIRE_MTLS || CONFIG_WENDY_BLE_SETUP
static struct os_mbuf read_info(enum info_field field)
{
    assert(test_services);
    const struct ble_gatt_chr_def *chr = test_services[0].characteristics;
    for (; chr->uuid; ++chr) {
        if (chr->arg != (void *)(uintptr_t)field)
            continue;
        struct os_mbuf result = {0};
        struct ble_gatt_access_ctxt ctx = {
            .op = BLE_GATT_ACCESS_OP_READ_CHR, .om = &result,
        };
        assert(chr->access_cb(0, 0, &ctx, chr->arg) == 0);
        return result;
    }
    assert(!"Missing GATT characteristic");
    return (struct os_mbuf){0};
}

static void assert_advertisement(uint8_t expected_mtls)
{
    const uint8_t service_uuid[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x59, 0x44, 0x4e, 0x45, 0x57, 0x4e,
    };
    assert(test_adv_starts == 1);
    assert(test_random_addresses == (unsigned)_setup);
    assert(test_adv_address_type == (_setup ? BLE_OWN_ADDR_RANDOM : 0));
    // Discovery filters on the service in the advertisement, not scan response.
    assert(test_adv.num_uuids128 == 1);
    assert(test_adv.uuids128_is_complete);
    const uint8_t setup_uuid[] = {
        0x32, 0xb6, 0x97, 0xb3, 0x08, 0xd7, 0x72, 0x92,
        0x67, 0x4b, 0x20, 0x4c, 0xeb, 0xe9, 0x65, 0x75,
    };
    bool setup = CONFIG_WENDY_BLE_SETUP && !expected_mtls;
    assert(memcmp(test_adv.uuids128->value, setup ? setup_uuid : service_uuid, 16) == 0);
    assert(test_rsp.mfg_data_len == 2 + strlen("lite-123"));
    assert(test_rsp.mfg_data[0] == 0xff && test_rsp.mfg_data[1] == 0xff);
    assert(memcmp(test_rsp.mfg_data + 2, "lite-123", strlen("lite-123")) == 0);
    assert(test_rsp.name_len == strlen("wendy-lite-123"));
    assert(memcmp(test_rsp.name, "wendy-lite-123", test_rsp.name_len) == 0);
    assert(test_rsp.mfg_data_len + test_rsp.name_len + 4 <= 31);
    struct os_mbuf mtls = read_info(INFO_MTLS);
    assert(mtls.len == 1 && mtls.data[0] == expected_mtls);
    struct os_mbuf id = read_info(INFO_DEVICE_ID);
    const char *expected_id = test_enrolled && test_enrollment_device_id[0]
        ? test_enrollment_device_id : "lite-123";
    assert(id.len == strlen(expected_id));
    assert(memcmp(id.data, expected_id, id.len) == 0);
    struct os_mbuf psm = read_info(INFO_PSM);
    assert(psm.len == 2 && psm.data[0] == (setup ? 131 : 128) && psm.data[1] == 0);
    assert(test_psm == (setup ? 131 : 128));
    // The enrolled principal carries the full device UUID; the hardware id
    // never stands in for it, and an unenrolled board publishes nothing.
    const char *principal = expected_mtls
        ? "spiffe://wendy.sh/tenant/00000000-0000-4000-8000-000000000001/device/00000000-0000-4000-8000-000000000004"
        : "";
    struct os_mbuf uri = read_info(INFO_PRINCIPAL);
    assert(uri.len == strlen(principal) && memcmp(uri.data, principal, uri.len) == 0);
}
#endif

static void test_pki_enrollment(void)
{
    // Enrollment advertises mTLS. Connection authentication checks the stored
    // identity. PKI-disabled builds reject enrollment at startup.
    reset_fixture();
    test_enrolled = true;
#if CONFIG_WENDY_PKI
    assert(wendy_ble_start() == ESP_OK);
    assert_advertisement(1);
    assert(test_task_calls == 1 && test_tasks_created == 1);
    assert(test_task_stack == 4096);
    assert(wendy_ble_start() == ESP_OK);
    assert(test_task_calls == 1 && test_tasks_created == 1);
    assert(test_semaphore_calls == 1);
#else
    assert(wendy_ble_start() == ESP_ERR_INVALID_STATE);
    assert(test_adv_starts == 0 && !_host_initialized);
#endif
}

static void test_unenrolled(void)
{
    reset_fixture();
    // A blank board has no readable configuration and can still allow setup.
    test_current = false;
#if CONFIG_WENDY_BLE_REQUIRE_MTLS && !CONFIG_WENDY_BLE_SETUP
    assert(wendy_ble_start() == ESP_ERR_INVALID_STATE);
    assert(test_adv_starts == 0 && !_host_initialized);
#else
    assert(wendy_ble_start() == ESP_OK);
    assert_advertisement(0);
    assert(test_task_calls == 1 && test_tasks_created == 1);
    assert(test_task_stack == (CONFIG_WENDY_BLE_SETUP ? 8192u : 4096u));
    assert(wendy_ble_start() == ESP_OK);
    assert(test_adv_starts == 1);
    assert(test_task_calls == 1 && test_tasks_created == 1);
    assert(test_semaphore_calls == 1);

#endif
}

static void test_empty_enrollment_identity(void)
{
#if CONFIG_WENDY_PKI
    reset_fixture();
    test_enrolled = true;
    test_enrollment_device_id[0] = '\0';
    assert(wendy_ble_start() == ESP_OK);
    assert_advertisement(1);
#endif
}

static void test_reset_blocks_start_and_restart(void)
{
    reset_fixture();
    test_reset = true;
    assert(wendy_ble_start() == ESP_ERR_INVALID_STATE);
    assert(test_adv_starts == 0 && !_host_initialized);

#if CONFIG_WENDY_PKI || !CONFIG_WENDY_BLE_REQUIRE_MTLS || CONFIG_WENDY_BLE_SETUP
    test_enrolled = CONFIG_WENDY_PKI;
    test_reset = false;
    assert(wendy_ble_start() == ESP_OK);
    assert_advertisement(CONFIG_WENDY_PKI);
    test_reset = true;
    struct ble_gap_event disconnect = { .type = BLE_GAP_EVENT_DISCONNECT };
    assert(_gap_event(&disconnect, NULL) == 0);
    assert(test_adv_starts == 1);
#endif
}

static void test_identity_change_blocks_restart(void)
{
#if !CONFIG_WENDY_BLE_REQUIRE_MTLS || CONFIG_WENDY_BLE_SETUP
    reset_fixture();
    assert(wendy_ble_start() == ESP_OK);
    assert_advertisement(0);
    struct ble_gap_event disconnect = { .type = BLE_GAP_EVENT_DISCONNECT };
    assert(_gap_event(&disconnect, NULL) == 0);
    assert(test_adv_starts == 2);
    test_enrolled = true;
    assert(wendy_ble_start() == ESP_ERR_INVALID_STATE);
    assert(!_enrolled);
    assert(_gap_event(&disconnect, NULL) == 0);
    assert(test_adv_starts == 2);
#endif

#if CONFIG_WENDY_PKI
    reset_fixture();
    test_enrolled = true;
    assert(wendy_ble_start() == ESP_OK);
    assert_advertisement(1);
    test_enrolled = false;
    assert(wendy_ble_start() == ESP_ERR_INVALID_STATE);
    assert(_enrolled);
    struct ble_gap_event enrolled_disconnect = { .type = BLE_GAP_EVENT_DISCONNECT };
    assert(_gap_event(&enrolled_disconnect, NULL) == 0);
    assert(test_adv_starts == 1);
#endif
}

static void test_allocation_failure_retry(void)
{
#if CONFIG_WENDY_PKI || !CONFIG_WENDY_BLE_REQUIRE_MTLS || CONFIG_WENDY_BLE_SETUP
    for (int enrolled = 0; enrolled <= CONFIG_WENDY_PKI; ++enrolled) {
        if (!enrolled && CONFIG_WENDY_BLE_REQUIRE_MTLS && !CONFIG_WENDY_BLE_SETUP)
            continue;
        for (int fail_task = 0; fail_task <= 1; ++fail_task) {
            reset_fixture();
            test_enrolled = enrolled;
            test_fail_semaphore = !fail_task;
            test_fail_task = fail_task;
            assert(wendy_ble_start() == ESP_ERR_NO_MEM);
            assert(!_started && _host_initialized);
            assert(!_device_id && !_device_name && !_display_name && !_link_closed);
            assert(test_adv_starts == 0 && test_tasks_created == 0);
            assert(test_semaphore_calls == 1);
            assert(test_semaphores_allocated == (unsigned)fail_task);
            assert(test_semaphores_deleted == test_semaphores_allocated);
            assert(test_task_calls == (unsigned)fail_task);

            // The NimBLE host survives the failed startup. A later sync must
            // still leave advertising off until the session task exists.
            assert(ble_hs_cfg.sync_cb);
            ble_hs_cfg.sync_cb();
            assert(test_adv_starts == 0);

            test_fail_semaphore = test_fail_task = false;
            assert(wendy_ble_start() == ESP_OK);
            assert_advertisement(enrolled);
            assert(test_tasks_created == 1);
            assert(test_task_calls == (unsigned)fail_task + 1);
            assert(test_task_stack == (enrolled || !CONFIG_WENDY_BLE_SETUP ? 4096u : 8192u));
            assert(test_semaphore_calls == 2);
            assert(test_semaphores_allocated == test_semaphores_deleted + 1);

            assert(wendy_ble_start() == ESP_OK);
            struct ble_gap_event disconnect = { .type = BLE_GAP_EVENT_DISCONNECT };
            assert(_gap_event(&disconnect, NULL) == 0);
            assert(test_adv_starts == 2);
            assert(test_tasks_created == 1);
            assert(test_task_calls == (unsigned)fail_task + 1);
            assert(test_semaphore_calls == 2);
        }
    }
#endif
}

static void test_invalidated_enrollment_cache(void)
{
    reset_fixture();
    test_enrolled = true;
    test_current = false;
    assert(wendy_ble_start() == ESP_ERR_INVALID_STATE);
    assert(test_adv_starts == 0 && !_host_initialized);

#if CONFIG_WENDY_PKI
    test_current = true;
    assert(wendy_ble_start() == ESP_OK);
    assert_advertisement(1);
    // A configuration write keeps enrollment required but invalidates its
    // cached data until reboot. It must revoke the captured advertising policy.
    test_current = false;
    assert(wendy_ble_start() == ESP_ERR_INVALID_STATE);
    assert(_enrolled && test_enrolled);
    struct ble_gap_event disconnect = { .type = BLE_GAP_EVENT_DISCONNECT };
    assert(_gap_event(&disconnect, NULL) == 0);
    assert(test_adv_starts == 1);
#endif
}

static void test_demand_handshake(void)
{
    for (int enrolled=0;enrolled<=CONFIG_WENDY_PKI;enrolled++) {
        reset_fixture();_enrolled=enrolled;
        test_handshake_calls=0;test_handshake_result=ESP_OK;
        assert(_run_session_handshake()==ESP_OK);
        assert(test_handshake_calls==1);
        assert(test_task_stack==(enrolled ? 24576u : 4096u));
        test_handshake_result=ESP_FAIL;
        assert(_run_session_handshake()==ESP_FAIL);
        assert(test_handshake_calls==2);
        test_fail_task=true;
        assert(_run_session_handshake()==ESP_ERR_NO_MEM);
        assert(test_handshake_calls==2);
    }
}

static unsigned test_receipts;
static void test_reply_complete(uint32_t token){assert(token==42);test_receipts++;}
static void test_reply_drain(void)
{
    test_receipts=0;test_l2cap_writable=false;
    _stream_ops.reply_barrier(NULL,42,test_reply_complete);
    assert(!test_receipts);(void)_stream_ops.can_read(NULL);assert(!test_receipts);
    test_l2cap_writable=true;
    (void)_stream_ops.can_read(NULL);assert(test_receipts==1);
    (void)_stream_ops.can_write(NULL);assert(test_receipts==1);
    test_l2cap_writable=false;
    _stream_ops.reply_barrier(NULL,42,test_reply_complete);
    _stream_ops.reply_barrier(NULL,42,test_reply_complete);
    assert(test_receipts==2); /* Old generation retires without another slot. */
    _link_closed=xSemaphoreCreateBinary();assert(_link_closed);
    _on_link_interruption(1,WCOM_INTERRUPTION_CONNECTION_CLOSED);
    assert(test_receipts==3&&!_reply_token);
    vSemaphoreDelete(_link_closed);_link_closed=NULL;
}

static void test_leftover_identity_blocks_setup(void)
{
#if CONFIG_WENDY_BLE_SETUP
    reset_fixture(); test_installed = true;
    assert(wendy_ble_start() == ESP_ERR_INVALID_STATE);
    assert(!test_adv_starts && !_host_initialized);
    reset_fixture(); test_challenge_fails = true;
    assert(wendy_ble_start() == ESP_ERR_INVALID_STATE);
    assert(!test_adv_starts && !_host_initialized);
#endif
}

static void test_setup_address_is_separate_and_stable(void)
{
#if CONFIG_WENDY_BLE_SETUP
    reset_fixture();
    assert(wendy_ble_start() == ESP_OK);
    assert(test_adv_address_type == BLE_OWN_ADDR_RANDOM);
    assert(test_random_addresses == 1);
    struct ble_gap_event disconnect = { .type = BLE_GAP_EVENT_DISCONNECT };
    _gap_event(&disconnect, NULL);
    _on_sync();
    assert(test_random_addresses == 1);
    assert(test_adv_starts == 3);
    assert(test_adv_address_type == BLE_OWN_ADDR_RANDOM);

    reset_fixture();
    test_fail_random_address = true;
    assert(wendy_ble_start() == ESP_OK);
    assert(!test_adv_starts && !_setup_address_ready);
    // Never fall back to the mesh's cached public address on RNG failure.
    test_fail_random_address = false;
    _on_sync();
    assert(test_adv_starts == 1 && _setup_address_ready);
    assert(test_adv_address_type == BLE_OWN_ADDR_RANDOM);
#endif
}

int main(void)
{
    test_reply_drain();
    test_demand_handshake();
    test_pki_enrollment();
    test_unenrolled();
    test_setup_address_is_separate_and_stable();
    test_leftover_identity_blocks_setup();
    test_empty_enrollment_identity();
    test_reset_blocks_start_and_restart();
    test_identity_change_blocks_restart();
    test_allocation_failure_retry();
    test_invalidated_enrollment_cache();
    reset_fixture();
    puts("BLE advertisement and GATT tests passed");
    return 0;
}
