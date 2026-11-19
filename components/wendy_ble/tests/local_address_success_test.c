/* ESP-Hosted supplies the radio identity; the host MCU's eFuse is unrelated. */
#define main existing_advertising_fixture_main
#include "advertising_test.c"
#undef main

int main(void)
{
    uint8_t address[6], type;
    assert(!wble_mesh_local_address(address, &type));
    for (unsigned i = 0; i < 6; i++)
        test_identity_address[i] = (uint8_t)(0xa0 + i);
    _on_sync();
    assert(wble_mesh_local_address(address, &type));
    assert(type == 0 && !memcmp(address, test_identity_address, 6));
    _on_reset(1);
    assert(!wble_mesh_local_address(address, &type));

    test_identity_type = 1;
    test_identity_address[0] = 0xb0;
    _on_sync();
    assert(wble_mesh_local_address(address, &type));
    assert(type == 1 && address[0] == 0xb0);
    _on_reset(1);
    test_identity_error = 1;
    _on_sync();
    assert(!wble_mesh_local_address(address, &type));
    puts("Controller address snapshots follow host synchronization and reset");
    return 0;
}
