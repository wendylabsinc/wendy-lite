/* Normal constrained startup keeps the physical WendyCom advertisement. */
#define main existing_advertising_fixture_main
#include "advertising_test.c"
#undef main
int main(void)
{
    test_pki_enrollment(); /* normal enrolled management service/GATT startup */
    assert(_started && _enrolled && test_adv_starts);
    assert(test_adv.num_uuids128==1 && test_adv.uuids128==&_uuid_svc);
    assert(wendy_ble_mesh_advertisement_idle());
    uint8_t mesh[30]={0};
    assert(wendy_ble_mesh_advertisement(mesh,sizeof mesh)==ESP_ERR_NOT_SUPPORTED);
    assert(wendy_ble_mesh_advertisement_idle() && !_mesh_advertisement_size);
    assert(!_primary_advertisement(true));
    assert(test_adv.num_uuids128==1 && test_adv.uuids128==&_uuid_svc);
    assert(!wendy_ble_mesh_advertisement(NULL,0));
    reset_fixture();puts("Constrained mesh publication stays off while WendyCom management advertising remains live");return 0;
}
