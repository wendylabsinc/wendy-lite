/* Exercise the production initializer with a remote controller in place of
 * the local controller used by the ordinary advertising fixture. */
#define main ordinary_advertisement_fixture_main
#include "advertising_test.c"
#undef main

static esp_hosted_coprocessor_fwver_t companion_version;
static esp_err_t connect_error, version_error, init_error, enable_error;
static unsigned connect_calls, init_calls, enable_calls, disable_calls, deinit_calls;

int esp_hosted_connect_to_slave(void)
{
    assert(!test_nimble_initialized);
    ++connect_calls;
    return connect_error;
}

int esp_hosted_get_coprocessor_fwversion(esp_hosted_coprocessor_fwver_t *version)
{
    assert(connect_calls && !test_nimble_initialized);
    *version = companion_version;
    return version_error;
}

esp_err_t esp_hosted_bt_controller_init(void)
{
    assert(!test_nimble_initialized);
    ++init_calls;
    return init_error;
}

esp_err_t esp_hosted_bt_controller_enable(void)
{
    assert(init_calls > deinit_calls && !test_nimble_initialized);
    ++enable_calls;
    return enable_error;
}

esp_err_t esp_hosted_bt_controller_disable(void)
{
    assert(enable_calls > disable_calls && !test_nimble_initialized);
    ++disable_calls;
    return ESP_OK;
}

esp_err_t esp_hosted_bt_controller_deinit(bool mem_release)
{
    assert(init_calls > deinit_calls && !mem_release && !test_nimble_initialized);
    ++deinit_calls;
    return ESP_OK;
}

static void reset_hosted(void)
{
    reset_fixture();
    companion_version = (esp_hosted_coprocessor_fwver_t){2, 13, 1};
    connect_error = version_error = init_error = enable_error = ESP_OK;
    test_nimble_init_error = ESP_OK;
    test_gatt_add_error = 0;
    connect_calls = init_calls = enable_calls = disable_calls = deinit_calls = 0;
}

int main(void)
{
    reset_hosted();
    version_error = ESP_FAIL;
    assert(wendy_ble_host_init() == ESP_OK);
    assert(connect_calls == 1 && test_nimble_initialized && !init_calls && !enable_calls);

    reset_hosted();
    companion_version = (esp_hosted_coprocessor_fwver_t){2, 5, 1};
    test_gatt_add_error = 1;
    assert(wendy_ble_host_init() == ESP_FAIL);
    assert(!test_nimble_initialized && !init_calls && !deinit_calls);
    test_gatt_add_error = 0;
    assert(wendy_ble_host_init() == ESP_OK && !init_calls && !enable_calls);

    reset_hosted();
    companion_version = (esp_hosted_coprocessor_fwver_t){2, 5, 2};
    assert(wendy_ble_host_init() == ESP_OK);
    assert(wendy_ble_host_init() == ESP_OK);
    assert(connect_calls == 1 && init_calls == 1 && enable_calls == 1 && !deinit_calls);

    reset_hosted();
    connect_error = ESP_FAIL;
    assert(wendy_ble_host_init() == ESP_FAIL);
    assert(!test_nimble_initialized && !init_calls);

    reset_hosted();
    init_error = ESP_ERR_INVALID_STATE;
    assert(wendy_ble_host_init() == ESP_ERR_INVALID_STATE);
    assert(init_calls == 1 && !test_nimble_initialized && !enable_calls && !deinit_calls);

    reset_hosted();
    enable_error = ESP_FAIL;
    assert(wendy_ble_host_init() == ESP_FAIL);
    assert(enable_calls == 1 && deinit_calls == 1 && !disable_calls && !test_nimble_initialized);

    reset_hosted();
    test_nimble_init_error = ESP_ERR_NO_MEM;
    assert(wendy_ble_host_init() == ESP_ERR_NO_MEM);
    assert(disable_calls == 1 && deinit_calls == 1 && !test_nimble_initialized);

    reset_hosted();
    test_gatt_add_error = 1;
    assert(wendy_ble_host_init() == ESP_FAIL);
    assert(disable_calls == 1 && deinit_calls == 1 && !test_nimble_initialized);
    test_gatt_add_error = 0;
    assert(wendy_ble_host_init() == ESP_OK);
    assert(init_calls == 2 && enable_calls == 2 && test_nimble_initialized);
    return 0;
}
