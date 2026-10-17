// Compile the transport itself so startup, GATT and restart regressions exercise
// the firmware code. No scheduler or radio runs in these host tests.
#include "../src/wendy_ble.c"

#include <stdio.h>

bool test_enrolled, test_provisioned, test_reset, test_invalid_cert;
unsigned test_auth_calls, test_adv_starts;
struct test_hs_cfg ble_hs_cfg;
struct ble_hs_adv_fields test_adv, test_rsp;
const struct ble_gatt_svc_def *test_services;

esp_err_t wble_l2cap_init(void) { return ESP_OK; }
bool wble_l2cap_wait_session(TickType_t timeout) { return false; }
void wble_l2cap_end_session(void) {}
int wble_l2cap_wakeup_fd(void) { return -1; }
bool wble_l2cap_can_read(void) { return false; }
bool wble_l2cap_can_write(void) { return false; }
esp_err_t wble_tls_session_start(void) { return ESP_FAIL; }
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
    _host_initialized = _started = _enrolled = _provisioned = false;
    _link_closed = NULL;
    _mfg_data_len = 0;
    test_enrolled = test_provisioned = test_reset = test_invalid_cert = false;
    test_auth_calls = test_adv_starts = 0;
    test_adv = (struct ble_hs_adv_fields){0};
    test_rsp = (struct ble_hs_adv_fields){0};
    test_services = NULL;
}

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
    // Discovery filters on the service in the advertisement, not scan response.
    assert(test_adv.num_uuids128 == 1);
    assert(test_adv.uuids128_is_complete);
    assert(memcmp(test_adv.uuids128->value, service_uuid, sizeof(service_uuid)) == 0);
    assert(test_rsp.mfg_data_len == 2 + strlen("lite-123"));
    assert(test_rsp.mfg_data[0] == 0xff && test_rsp.mfg_data[1] == 0xff);
    assert(memcmp(test_rsp.mfg_data + 2, "lite-123", strlen("lite-123")) == 0);
    assert(test_rsp.name_len == strlen("wendy-lite-123"));
    assert(memcmp(test_rsp.name, "wendy-lite-123", test_rsp.name_len) == 0);
    assert(test_rsp.mfg_data_len + test_rsp.name_len + 4 <= 31);
    struct os_mbuf mtls = read_info(INFO_MTLS);
    assert(mtls.len == 1 && mtls.data[0] == expected_mtls);
    struct os_mbuf id = read_info(INFO_DEVICE_ID);
    assert(id.len == strlen("lite-123"));
    assert(memcmp(id.data, "lite-123", id.len) == 0);
    struct os_mbuf psm = read_info(INFO_PSM);
    assert(psm.len == 2 && psm.data[0] == 128 && psm.data[1] == 0);
}

static void test_pki_enrollment(void)
{
    // An enrollment is sufficient even when legacy credentials are absent or
    // invalid. PKI-disabled builds must still reject enrolled identities.
    for (int legacy = 0; legacy <= 1; ++legacy) {
        reset_fixture();
        test_enrolled = true;
        test_provisioned = legacy;
        test_invalid_cert = true;
#if CONFIG_WENDY_PKI
        assert(wendy_ble_start() == ESP_OK);
        assert_advertisement(1);
#else
        assert(wendy_ble_start() == ESP_ERR_INVALID_STATE);
        assert(test_adv_starts == 0 && !_host_initialized);
#endif
        assert(test_auth_calls == 0);
    }
}

static void test_legacy_and_unprovisioned(void)
{
    reset_fixture();
    test_provisioned = true;
    assert(wendy_ble_start() == ESP_OK);
    assert(test_auth_calls == 1);
    assert_advertisement(1);
    assert(wendy_ble_start() == ESP_OK);
    assert(test_adv_starts == 1);

    reset_fixture();
    test_provisioned = true;
    test_invalid_cert = true;
    assert(wendy_ble_start() == ESP_ERR_INVALID_STATE);
    assert(test_auth_calls == 1);
    assert(test_adv_starts == 0 && !_host_initialized);

    reset_fixture();
#if CONFIG_WENDY_BLE_REQUIRE_MTLS
    assert(wendy_ble_start() == ESP_ERR_INVALID_STATE);
    assert(test_adv_starts == 0 && !_host_initialized);
#else
    assert(wendy_ble_start() == ESP_OK);
    assert_advertisement(0);
#endif
}

static void test_reset_blocks_start_and_restart(void)
{
    reset_fixture();
    test_provisioned = true;
    test_reset = true;
    assert(wendy_ble_start() == ESP_ERR_INVALID_STATE);
    assert(test_adv_starts == 0 && !_host_initialized);

    test_reset = false;
    assert(wendy_ble_start() == ESP_OK);
    assert_advertisement(1);
    test_reset = true;
    struct ble_gap_event disconnect = { .type = BLE_GAP_EVENT_DISCONNECT };
    assert(_gap_event(&disconnect, NULL) == 0);
    assert(test_adv_starts == 1);
}

static void test_identity_change_blocks_restart(void)
{
    reset_fixture();
    test_provisioned = true;
    assert(wendy_ble_start() == ESP_OK);
    assert_advertisement(1);
    struct ble_gap_event disconnect = { .type = BLE_GAP_EVENT_DISCONNECT };
    assert(_gap_event(&disconnect, NULL) == 0);
    assert(test_adv_starts == 2);
    test_enrolled = true;
    assert(wendy_ble_start() == ESP_ERR_INVALID_STATE);
    assert(!_enrolled && _provisioned);
    assert(_gap_event(&disconnect, NULL) == 0);
    assert(test_adv_starts == 2);
    test_enrolled = false;
    test_provisioned = false;
    assert(wendy_ble_start() == ESP_ERR_INVALID_STATE);
    assert(!_enrolled && _provisioned);
    assert(_gap_event(&disconnect, NULL) == 0);
    assert(test_adv_starts == 2);

#if CONFIG_WENDY_PKI
    reset_fixture();
    test_enrolled = true;
    assert(wendy_ble_start() == ESP_OK);
    assert_advertisement(1);
    test_enrolled = false;
    assert(wendy_ble_start() == ESP_ERR_INVALID_STATE);
    assert(_enrolled && !_provisioned);
    assert(_gap_event(&disconnect, NULL) == 0);
    assert(test_adv_starts == 1);
#endif
}

int main(void)
{
    test_pki_enrollment();
    test_legacy_and_unprovisioned();
    test_reset_blocks_start_and_restart();
    test_identity_change_blocks_restart();
    reset_fixture();
    puts("BLE advertisement and GATT tests passed");
    return 0;
}
