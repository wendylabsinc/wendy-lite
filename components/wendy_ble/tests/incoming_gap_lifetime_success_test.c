/* Ordinary rejected channels must not occupy every controller slot forever. */
#define main existing_advertising_fixture_main
#include "advertising_test.c"
#undef main
static void connect_incoming(uint16_t handle)
{
    struct ble_gap_event e={.type=BLE_GAP_EVENT_CONNECT};
    e.connect.conn_handle=handle;_gap_event(&e,NULL);
}
static void disconnect_incoming(uint16_t handle)
{
    struct ble_gap_event e={.type=BLE_GAP_EVENT_DISCONNECT};
    e.disconnect.conn.conn_handle=handle;_gap_event(&e,NULL);
}
int main(void)
{
    test_pki_enrollment();uint8_t mesh[30]={0};
    assert(!wendy_ble_mesh_advertisement(mesh,sizeof mesh));
    unsigned tasks=test_tasks_created;test_now_us=1000;connect_incoming(1);
    test_now_us+=29000000;_mesh_adv_refresh(NULL);assert(!test_gap_terminations);
    /* Legitimate GATT selection refreshes its lease before opening a CoC. */
    struct os_mbuf out={0};struct ble_gatt_access_ctxt g={.op=BLE_GATT_ACCESS_OP_READ_CHR,.om=&out};
    assert(!_info_access(1,0,&g,(void *)(uintptr_t)INFO_DEVICE_ID));
    test_now_us+=2000000;_mesh_adv_refresh(NULL);assert(!test_gap_terminations);
    test_now_us+=30000000;
    /* Physical, pending/active/closing mesh, shared and signed-time channels
     * are conservatively claimed; the host never disconnects their ACL. */
    test_physical_claim=true;_mesh_adv_refresh(NULL);assert(!test_gap_terminations);
    test_mesh_claim=true;test_physical_claim=false;_mesh_adv_refresh(NULL);assert(!test_gap_terminations);
    test_physical_claim=true;_mesh_adv_refresh(NULL);assert(!test_gap_terminations);
    test_physical_claim=false;test_mesh_claim=false;
    test_reset=true;_mesh_adv_refresh(NULL);assert(!test_gap_terminations);
    test_reset=false;test_current=false;_mesh_adv_refresh(NULL);assert(!test_gap_terminations);
    test_advertising_active=false;test_advertising_error=BLE_HS_ENOMEM;
    test_current=true;_mesh_adv_refresh(NULL);assert(test_gap_terminations==1 && test_gap_terminated_handle==1);
    _mesh_adv_refresh(NULL);assert(test_gap_terminations==1); /* wait for ACK */
    test_advertising_error=0;disconnect_incoming(1);assert(test_advertising_active);
    connect_incoming(1); /* ordinary handle reuse after disconnect ACK */
    assert(_incoming_gaps[0].used && !_incoming_gaps[0].terminating);
    test_now_us+=30000001;_mesh_adv_refresh(NULL);assert(test_gap_terminations==2);
    disconnect_incoming(1);connect_incoming(2);
    /* OFF removes the existing timer; late events cannot expire baseline
     * metadata-only connections or resurrect a mesh timer. */
    assert(!wendy_ble_mesh_advertisement(NULL,0));test_now_us+=60000000;
    _mesh_adv_refresh(NULL);assert(test_gap_terminations==2 && !_mesh_adv_timer);
    _on_reset(1);for(size_t i=0;i<3;i++)assert(!_incoming_gaps[i].used);
    assert(test_tasks_created==tasks);reset_fixture();
    puts("Incoming GAP idle leases preserve GATT/channel claims, reclaim refused idle slots and honor OFF/reset/handle reuse");return 0;
}
