/* Ordinary full-peer startup hits transient controller capacity, then a
 * mesh-owned outgoing GAP retires without a physical management callback. */
#define main existing_advertising_fixture_main
#include "advertising_test.c"
#undef main
int main(void)
{
    test_pki_enrollment();assert(_started && _enrolled && test_adv_starts);
    uint8_t mesh[30]={0};assert(wendy_ble_mesh_advertisement(mesh,sizeof mesh)==ESP_OK);
    esp_timer_handle_t timer=_mesh_adv_timer;assert(timer && test_timer_period==500000);
    unsigned tasks=test_tasks_created;
    test_advertising_active=false;test_advertising_error=BLE_HS_HCI_ERR(BLE_ERR_MEM_CAPACITY);
    unsigned attempts=test_adv_starts;_start_advertising(false);assert(test_adv_starts==attempts+1);
    _mesh_adv_refresh(NULL);assert(!test_advertising_active && _mesh_adv_timer==timer);
    assert(test_timer_period==5000000 && test_timer_restarts==1);
    /* The slot is freed on a different connection's callback. This already
     * existing timer event recovers management and normal500ms rotation. */
    test_advertising_error=0;_mesh_adv_refresh(NULL);
    assert(test_advertising_active && _mesh_adv_timer==timer && test_timer_period==500000);
    assert(test_tasks_created==tasks);
    attempts=test_adv_starts;_mesh_adv_refresh(NULL);assert(test_adv_starts==attempts);
    test_advertising_active=false;test_reset=true;_mesh_adv_refresh(NULL);assert(test_adv_starts==attempts);
    test_reset=false;test_current=false;_mesh_adv_refresh(NULL);assert(test_adv_starts==attempts);
    test_current=true;
    /* OFF restores normal management payload and deletes the mesh timer;
     * it never resurrects advertising from a stopped/late mesh event. */
    assert(!wendy_ble_mesh_advertisement(NULL,0));assert(!_mesh_adv_timer && test_adv_starts==attempts);
    _started=false;_mesh_adv_refresh(NULL);assert(!_mesh_adv_timer && test_adv_starts==attempts);
    reset_fixture();puts("Full-peer management advertising recovers after transient capacity using its existing timer; OFF/current identity preserved");return 0;
}
