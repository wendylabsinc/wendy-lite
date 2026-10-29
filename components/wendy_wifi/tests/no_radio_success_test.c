/* Reuse the normal WiFi SDK adapter; this target exercises only boot profile
 * behavior, never the recovery/failure scenarios in its original main. */
#define main normal_wifi_adapter_main
#include "services_test.c"
#undef main
int main(void)
{
#if !TEST_BOOT_RADIO_DISABLED
    assert(wendy_wifi_radio_available());
    assert(wifi_infra_init()==ESP_OK && wifi_infra_init()==ESP_OK);
    assert(netif_inits==1 && event_loop_inits==1 && station_netifs==1);
    assert(driver_inits==1 && task_creates==1 && !server_starts);
    assert(wendy_wifi_set_boot_radio_enabled(false)==ESP_ERR_INVALID_STATE);
    assert(!credential_opens);
    puts("Normal boot retains idempotent WiFi infrastructure initialization");
    return 0;
#else
    assert(wendy_wifi_set_boot_radio_enabled(false)==ESP_OK);
    assert(!wendy_wifi_radio_available());
    assert(wendy_wifi_init()==ESP_OK);
    assert(wendy_wifi_init()==ESP_OK);
    assert(netif_inits==1 && event_loop_inits==1 && server_starts==1);
    assert(wendy_wifi_set_boot_radio_enabled(true)==ESP_ERR_INVALID_STATE);
    assert(!station_netifs && !driver_inits && !task_creates);
    assert(!mdns_inits && !hostname_sets && !cloud_starts && !credential_opens);
    assert(!wendy_wifi_is_connected());
    assert(wendy_wifi_try_connect("unchanged-network","unchanged-password")==ESP_ERR_NOT_SUPPORTED);
    assert(wendy_wifi_set_station_enabled(true)==ESP_ERR_NOT_SUPPORTED);
    assert(wendy_wifi_set_station_enabled(false)==ESP_OK);
    wendy_wifi_deinit();
    assert(wendy_wifi_init()==ESP_OK);
    assert(netif_inits==1 && event_loop_inits==1 && server_starts==1);
    assert(!driver_inits && !driver_starts && !credential_opens && !credential_saves);
    puts("No-radio boot keeps shared IP/listener without WiFi, services, mDNS or credential I/O");
    return 0;
#endif
}
