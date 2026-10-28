#include "../src/wendy_ble_l2cap.c"
#include <stdio.h>

struct ble_npl_event *test_queued;
bool test_on_host;
void (*test_before_host_event)(void);
unsigned test_gap_closes, test_channel_closes;
uint16_t test_closed_peer;
static struct ble_l2cap_chan channels[2];

static void connected(int index, uint16_t peer)
{
    struct ble_l2cap_event e = { .type = BLE_L2CAP_EVENT_COC_CONNECTED };
    e.connect.chan = &channels[index]; e.connect.conn_handle = peer;
    _l2cap_event(&e, NULL);
}
static void channel_closed(int index)
{
    struct ble_l2cap_event e = { .type = BLE_L2CAP_EVENT_COC_DISCONNECTED };
    e.disconnect.chan = &channels[index];
    _l2cap_event(&e, NULL);
}
static void peer_disappears_before_teardown(void)
{
    channel_closed(0);
    wble_l2cap_peer_disconnected(7);
}
int main(void)
{
    _mutex = xSemaphoreCreateMutex();
    _session_sem = xSemaphoreCreateBinary();
    _rx_sem = xSemaphoreCreateBinary(); _tx_sem = xSemaphoreCreateBinary();
    _end_sem = xSemaphoreCreateBinary();
    ble_npl_event_init(&_end_event, _end_session_on_host, NULL);

    connected(0, 7);
    assert(wble_l2cap_wait_session(0));
    wble_l2cap_end_session(true);
    assert(test_gap_closes == 1 && test_closed_peer == 7);
    assert(!test_channel_closes && !_session_active);

    // A peer closing only its channel must not retain GAP or reopen L2CAP
    // before the previous setup task has finished using its session state.
    connected(0, 7); channel_closed(0);
    assert(wble_l2cap_wait_session(0));
    struct ble_l2cap_event accept = { .type = BLE_L2CAP_EVENT_COC_ACCEPT };
    accept.accept.chan = &channels[1];
    assert(_l2cap_event(&accept, NULL) == BLE_HS_ENOMEM);
    wble_l2cap_end_session(true);
    assert(test_gap_closes == 2);

    // A delayed teardown must not terminate a reused connection handle.
    connected(0, 7);
    test_before_host_event = peer_disappears_before_teardown;
    wble_l2cap_end_session(true);
    test_before_host_event = NULL;
    assert(test_gap_closes == 2);

    // The delayed disconnect event for an old channel must not clear the new
    // channel. Enrolled management still closes only L2CAP, not GAP.
    connected(1, 8); channel_closed(0);
    assert(wble_l2cap_session_alive());
    wble_l2cap_end_session(false);
    assert(test_channel_closes == 1 && test_gap_closes == 2);
    assert(!_session_active && _session_peer == BLE_HS_CONN_HANDLE_NONE);
    free(_mutex); free(_session_sem); free(_rx_sem); free(_tx_sem); free(_end_sem);
    puts("L2CAP teardown, retry exclusion and handle reuse tests passed");
}
