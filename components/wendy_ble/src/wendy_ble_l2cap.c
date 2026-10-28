#include "wendy_ble_l2cap.h"

#include <string.h>
#include <unistd.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "esp_vfs_eventfd.h"
#include "freertos/semphr.h"

#include "host/ble_hs.h"
#include "host/ble_gap.h"
#include "host/ble_l2cap.h"
#include "os/os_mbuf.h"
#include "os/os_mempool.h"
#include "nimble/ble.h"
#include "nimble/nimble_port.h"


//--- literals ---//

#define TAG  "wendy_ble_l2cap"

#define MTU        CONFIG_WENDY_BLE_MTU

// Two SDUs' worth: mbedTLS reads a record header and then its body, so a
// single SDU is routinely consumed by more than one read, and a second SDU can
// land while the first is still being drained.
#define RING_SIZE  (2 * MTU)

// One receive buffer parked with the stack, one in flight through the receive
// event, and room for a couple of transmits queued behind a credit stall. A
// dedicated pool rather than msys: an MTU-sized allocation out of msys chains
// many small blocks and competes with ATT traffic.
#define SDU_COUNT  6
#define SDU_BLOCK_SIZE (MTU + BLE_MBUF_MEMBLOCK_OVERHEAD)

// Largest SDU we transmit, chosen so one SDU is one L2CAP PDU, one HCI ACL
// fragment and one link-layer packet: 245 + 2 (SDU length) + 4 (L2CAP header)
// = 251, the most a data PDU carries once the data length extension is
// negotiated, and under the 255-byte ACL packet the host fragments to.
//
// Anything larger is refragmented inside the host, and every fragment is
// chained out of the 128-byte msys pool — ble_hs_mbuf_l2cap_pkt() asks msys
// for a zero-length packet, which always lands in the smallest pool, and
// os_mbuf_append() then extends the chain from that same pool. A 512-byte SDU
// costs about nine of the twelve blocks that exist, held until the controller
// drains them, which is what makes ble_l2cap_send() return ENOMEM under load.
// The link layer sends 251-byte packets either way, so chunking here costs no
// throughput.
#define TX_SDU_MAX  245

// How long to hold transmits off when the host runs out of mbufs, and how long
// to keep doing that before calling the link dead. The host releases those
// blocks as the controller acknowledges the packets it is already holding,
// which happens on the following connection events, so the wait is one
// connection interval rather than a guess at a queue depth.
#define TX_BACKOFF_MS   10
#define TX_BACKOFF_MAX  200   // ~2 s; past this the shortage is not transient


//--- globals ---//

static os_membuf_t          _sdu_mem[OS_MEMPOOL_SIZE(SDU_COUNT, SDU_BLOCK_SIZE)];
static struct os_mempool    _sdu_mempool;
static struct os_mbuf_pool  _sdu_mbuf_pool;

static SemaphoreHandle_t _mutex;
static SemaphoreHandle_t _session_sem;
static SemaphoreHandle_t _rx_sem;
static SemaphoreHandle_t _tx_sem;
static SemaphoreHandle_t _end_sem;
static struct ble_npl_event _end_event;
static esp_timer_handle_t _tx_backoff_timer;
static int _wakeup_fd = -1;

/* Guarded by _mutex. */
static struct ble_l2cap_chan *_chan;
static bool _session_active;
static uint16_t _session_peer = BLE_HS_CONN_HANDLE_NONE;
static bool _disconnect_peer;
static uint16_t _tx_mtu;
static bool     _tx_stalled;
static bool     _tx_backoff;        // out of host mbufs; holding transmits off
static unsigned _tx_backoff_count;  // consecutive hold-offs, reset on a send
static bool     _peer_gone;        // channel closed; drain the ring, then EOF
static bool     _rx_retry;
static struct ble_npl_event _rx_rearm_event;
static bool     _recv_ready_owed;  // the stack is waiting on us for a buffer
static uint8_t  _ring[RING_SIZE];
static size_t   _ring_head;
static size_t   _ring_len;


//--- internal functions ---//

static inline size_t _ring_free(void)
{
    return RING_SIZE - _ring_len;
}

static void _lock(void)   { xSemaphoreTake(_mutex, portMAX_DELAY); }
static void _unlock(void) { xSemaphoreGive(_mutex); }

bool wble_l2cap_uses_connection(uint16_t handle)
{
    if (!_mutex)
        return false;
    _lock();
    bool used = _chan && ble_l2cap_get_conn_handle(_chan) == handle;
    _unlock();
    return used;
}

bool wble_l2cap_connection_idle(uint16_t handle)
{
    if(!_mutex)return true;
    if(xSemaphoreTake(_mutex,0)!=pdTRUE)return false;
    bool idle=!_chan || ble_l2cap_get_conn_handle(_chan)!=handle;
    _unlock();
    return idle;
}

/// Wake anything waiting on this channel. The eventfd is edge-ish (a counter
/// the reader drains) but every waiter re-derives readiness from the state
/// afterwards, so an extra wakeup is free and a missed one is impossible as
/// long as this runs after the state change.
static void _signal(SemaphoreHandle_t sem)
{
    if (sem)
        xSemaphoreGive(sem);
    if (_wakeup_fd >= 0) {
        uint64_t one = 1;
        (void)write(_wakeup_fd, &one, sizeof(one));
    }
}

/// End of a transmit hold-off. Runs on the esp_timer task.
static void _tx_backoff_expired(void *arg)
{
    (void)arg;
    _lock();
    _tx_backoff = false;
    _rx_retry = false;
    _unlock();
    ble_npl_eventq_put(nimble_port_get_dflt_eventq(),&_rx_rearm_event);
    _signal(_rx_sem);
    _signal(_tx_sem);
}

/// Hand the stack a fresh receive buffer. Only ever called with at least one
/// MTU free in the ring, so a full SDU always fits when it arrives — that is
/// what turns the ring into the channel's flow control.
static int _arm_recv(struct ble_l2cap_chan *chan)
{
    struct os_mbuf *sdu = os_mbuf_get_pkthdr(&_sdu_mbuf_pool, 0);
    if (!sdu) {
        ESP_LOGD(TAG, "SDU pool exhausted arming receive");
        return BLE_HS_ENOMEM;
    }
    int rc=ble_l2cap_recv_ready(chan,sdu);
    /* EBUSY refuses before adopting the buffer; an already armed SDK RX
     * slot still backs the peer's credits. ENOENT occurs after adoption. */
    if(rc==BLE_HS_EBUSY)os_mbuf_free_chain(sdu);
    return rc;

}

/* All receive rearm attempts after ACCEPT run on the existing NimBLE host
 * queue. Keep owed until acceptance; a transient pool refusal must not leave
 * the remote with zero credits and no future event capable of retrying. */
static void _rx_rearm_host(struct ble_npl_event *event)
{
    (void)event;
    _lock();
    if(!_chan || !_recv_ready_owed || _rx_retry || _ring_free()<MTU){_unlock();return;}
    /* Holding the adapter mutex keeps I/O end_session from releasing this
     * channel while recv_ready runs. SDK recv_ready invokes no app callback. */
    int rc=_arm_recv(_chan);
    bool retry=rc && rc!=BLE_HS_EBUSY;
    _recv_ready_owed=retry;
    _rx_retry=retry;
    _unlock();
    if(retry){
        esp_err_t err=esp_timer_start_once(_tx_backoff_timer,TX_BACKOFF_MS*1000);
        /* An already queued shared backoff callback will retry both sides. */
        if(err!=ESP_OK && err!=ESP_ERR_INVALID_STATE){
            _lock();_rx_retry=false;_unlock();_signal(_rx_sem);
        }
    }
}

/// Copy an SDU into the ring. Caller holds the lock.
static void _ring_append(struct os_mbuf *sdu)
{
    size_t len = OS_MBUF_PKTLEN(sdu);
    if (len > _ring_free()) {
        // Can't happen: a buffer is only ever armed with >= MTU free and the
        // peer cannot exceed the MTU it was told. Drop rather than corrupt.
        ESP_LOGE(TAG, "ring overflow: %u bytes, %u free — dropping",
                 (unsigned)len, (unsigned)_ring_free());
        return;
    }

    size_t tail = (_ring_head + _ring_len) % RING_SIZE;
    size_t first = RING_SIZE - tail;
    if (first > len)
        first = len;

    os_mbuf_copydata(sdu, 0, first, &_ring[tail]);
    if (len > first)
        os_mbuf_copydata(sdu, first, len - first, &_ring[0]);

    _ring_len += len;
}

static int _l2cap_event(struct ble_l2cap_event *event, void *arg)
{
    (void)arg;

    switch (event->type) {
        case BLE_L2CAP_EVENT_COC_ACCEPT: {
            _lock();
            bool busy = _session_active;
            _unlock();
            if (busy) {
                ESP_LOGW(TAG, "rejecting second L2CAP channel");
                return BLE_HS_ENOMEM;
            }
            // Returning non-zero here refuses the channel, so the buffer must
            // be armed before the stack completes the connection.
            return _arm_recv(event->accept.chan);
        }

        case BLE_L2CAP_EVENT_COC_CONNECTED: {
            if (event->connect.status != 0) {
                ESP_LOGE(TAG, "L2CAP connect failed: %d", event->connect.status);
                return 0;
            }
            struct ble_l2cap_chan_info info;
            uint16_t tx_mtu = MTU;
            uint16_t peer_mps = 0;
            if (ble_l2cap_get_chan_info(event->connect.chan, &info) == 0) {
                // An SDU larger than what the peer advertised is rejected
                // outright, so this is a hard bound, not a preference.
                tx_mtu = info.peer_coc_mtu < MTU ? info.peer_coc_mtu : MTU;
                peer_mps = info.peer_l2cap_mtu;
            }
            _lock();
            _chan = event->connect.chan;
            _session_active = true;
            _session_peer = event->connect.conn_handle;
            _tx_mtu = tx_mtu;
            _tx_stalled = false;
            _tx_backoff = false;
            _tx_backoff_count = 0;
            _peer_gone = false;
            _recv_ready_owed = false;
            _rx_retry = false;
            _ring_head = 0;
            _ring_len = 0;
            _unlock();
            // The mbuf count is the baseline for the "msys free" figure in the
            // transmit error path: a session that starts lower than the last
            // one means blocks are not coming back.
            ESP_LOGI(TAG,
                     "L2CAP channel open (tx mtu %u, peer mps %u, sdu %u, "
                     "msys %d/%d mbufs free)",
                     (unsigned)tx_mtu, (unsigned)peer_mps,
                     (unsigned)(tx_mtu < TX_SDU_MAX ? tx_mtu : TX_SDU_MAX),
                     os_msys_num_free(), os_msys_count());
            _signal(_session_sem);
            return 0;
        }

        case BLE_L2CAP_EVENT_COC_DISCONNECTED:
            ESP_LOGI(TAG, "L2CAP channel closed (msys %d/%d mbufs free)",
                     os_msys_num_free(), os_msys_count());
            _lock();
            if (_chan != event->disconnect.chan) {
                _unlock();
                return 0;
            }
            _chan = NULL;
            _recv_ready_owed = false;
            _rx_retry = false;
            _peer_gone = true;
            _unlock();
            _signal(_rx_sem);
            _signal(_tx_sem);
            _signal(_session_sem);
            return 0;

        case BLE_L2CAP_EVENT_COC_DATA_RECEIVED: {
            struct os_mbuf *sdu = event->receive.sdu_rx;
            if (!sdu)
                return 0;

            _lock();
            _ring_append(sdu);
            bool room = _ring_free() >= MTU;
            _recv_ready_owed = true;
            _unlock();

            os_mbuf_free_chain(sdu);

            // Withholding the next buffer is the backpressure: the peer runs
            // out of credits until a reader drains the ring.
            if (room)
                ble_npl_eventq_put(nimble_port_get_dflt_eventq(),&_rx_rearm_event);

            _signal(_rx_sem);
            return 0;
        }

        case BLE_L2CAP_EVENT_COC_TX_UNSTALLED:
            _lock();
            _tx_stalled = false;
            _unlock();
            _signal(_tx_sem);
            return 0;

        default:
            return 0;
    }
}

// Run teardown on NimBLE's host queue, serialized with GAP disconnects and
// handle reuse. The session task waits for completion before serving a new
// channel; a peer cannot reopen L2CAP while the previous session cleans up.
static void _end_session_on_host(struct ble_npl_event *event)
{
    (void)event;
    _lock();
    struct ble_l2cap_chan *chan = _chan;
    uint16_t peer = _session_peer;
    bool disconnect_peer = _disconnect_peer;
    _chan = NULL;
    _session_active = false;
    _session_peer = BLE_HS_CONN_HANDLE_NONE;
    _peer_gone = false;
    _tx_stalled = false;
    _tx_backoff = false;
    _tx_backoff_count = 0;
    _recv_ready_owed = false;
    _rx_retry = false;
    _ring_head = 0;
    _ring_len = 0;
    _unlock();

    if (disconnect_peer && peer != BLE_HS_CONN_HANDLE_NONE) {
        int rc = ble_gap_terminate(peer, BLE_ERR_REM_USER_CONN_TERM);
        if (rc != 0 && rc != BLE_HS_ENOTCONN) {
            ESP_LOGW(TAG, "setup peer disconnect failed: %d", rc);
            if (chan) ble_l2cap_disconnect(chan);
        }
    } else if (chan) {
        ble_l2cap_disconnect(chan);
    }
    xSemaphoreGive(_end_sem);
}


//--- public functions ---//

esp_err_t wble_l2cap_init(uint16_t psm)
{
    if (_wakeup_fd >= 0)
        return ESP_OK;

    int rc = os_mempool_init(&_sdu_mempool, SDU_COUNT, SDU_BLOCK_SIZE, _sdu_mem,
                             "wendy_ble_sdu");
    if (rc != 0) {
        ESP_LOGE(TAG, "os_mempool_init failed: %d", rc);
        return ESP_FAIL;
    }
    rc = os_mbuf_pool_init(&_sdu_mbuf_pool, &_sdu_mempool, SDU_BLOCK_SIZE, SDU_COUNT);
    if (rc != 0) {
        ESP_LOGE(TAG, "os_mbuf_pool_init failed: %d", rc);
        return ESP_FAIL;
    }

    _mutex       = xSemaphoreCreateMutex();
    _session_sem = xSemaphoreCreateBinary();
    _rx_sem      = xSemaphoreCreateBinary();
    _tx_sem      = xSemaphoreCreateBinary();
    _end_sem     = xSemaphoreCreateBinary();
    if (!_mutex || !_session_sem || !_rx_sem || !_tx_sem || !_end_sem) {
        ESP_LOGE(TAG, "semaphore allocation failed");
        return ESP_ERR_NO_MEM;
    }
    ble_npl_event_init(&_end_event, _end_session_on_host, NULL);

    ble_npl_event_init(&_rx_rearm_event,_rx_rearm_host,NULL);
    const esp_timer_create_args_t backoff_args = {
        .callback = _tx_backoff_expired,
        .name     = "wble_tx_backoff",
    };
    esp_err_t err = esp_timer_create(&backoff_args, &_tx_backoff_timer);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_timer_create failed: %s", esp_err_to_name(err));
        return err;
    }

    _wakeup_fd = eventfd(0, 0);
    if (_wakeup_fd < 0) {
        ESP_LOGE(TAG, "eventfd() failed");
        return ESP_FAIL;
    }
    // Left blocking on purpose: ESP-IDF's eventfd VFS implements no fcntl, so
    // it cannot be made non-blocking. Nothing here ever reads it — draining is
    // wcom's job, and wcom only reads it after select() has said it is
    // readable, which is what keeps a blocking read safe.

    rc = ble_l2cap_create_server(psm, MTU, _l2cap_event, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_l2cap_create_server failed: %d", rc);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "L2CAP server listening on PSM %d (mtu %d)",
             psm, MTU);
    return ESP_OK;
}

bool wble_l2cap_wait_session(TickType_t timeout)
{
    _lock();
    bool active = _session_active;
    _unlock();
    if (active)
        return true;
    xSemaphoreTake(_session_sem, timeout);
    _lock();
    active = _session_active;
    _unlock();
    return active;
}

bool wble_l2cap_session_alive(void)
{
    _lock();
    bool alive = (_chan != NULL);
    _unlock();
    return alive;
}

void wble_l2cap_peer_disconnected(uint16_t conn_handle)
{
    if (!_mutex) return;
    _lock();
    if (_session_peer == conn_handle) {
        _session_peer = BLE_HS_CONN_HANDLE_NONE;
        _chan = NULL;
        _peer_gone = true;
    }
    _unlock();
    _signal(_rx_sem);
    _signal(_tx_sem);
}

void wble_l2cap_end_session(bool disconnect_peer)
{
    _lock();
    _disconnect_peer = disconnect_peer;
    _unlock();
    ble_npl_eventq_put(nimble_port_get_dflt_eventq(), &_end_event);
    xSemaphoreTake(_end_sem, portMAX_DELAY);

    // A leftover count on the wakeup fd is deliberately left alone: reading it
    // here could block (see wble_l2cap_init), and all it can cause is one
    // early wakeup in the next session, where can_read()/can_write() report
    // the real state anyway.
}

ssize_t wble_l2cap_read(void *buf, size_t len)
{
    if (len == 0)
        return 0;

    _lock();
    size_t n = _ring_len < len ? _ring_len : len;
    if (n > 0) {
        size_t first = RING_SIZE - _ring_head;
        if (first > n)
            first = n;
        memcpy(buf, &_ring[_ring_head], first);
        if (n > first)
            memcpy((uint8_t *)buf + first, &_ring[0], n - first);
        _ring_head = (_ring_head + n) % RING_SIZE;
        _ring_len -= n;
    }
    bool rearm = _recv_ready_owed && !_rx_retry && _ring_free() >= MTU && _chan != NULL;
    bool gone = _peer_gone;
    _unlock();

    if (rearm)
        ble_npl_eventq_put(nimble_port_get_dflt_eventq(),&_rx_rearm_event);

    if (n > 0)
        return (ssize_t)n;
    return gone ? 0 : WBLE_ERR_WANT_READ;
}

ssize_t wble_l2cap_write(const void *buf, size_t len)
{
    if (len == 0)
        return 0;

    _lock();
    struct ble_l2cap_chan *chan = _chan;
    bool hold = _tx_stalled || _tx_backoff;
    size_t cap = _tx_mtu < TX_SDU_MAX ? _tx_mtu : TX_SDU_MAX;
    size_t n = len < cap ? len : cap;
    _unlock();

    if (!chan)
        return WBLE_ERR_UNKNOWN;
    if (hold)
        return WBLE_ERR_WANT_WRITE;

    struct os_mbuf *sdu = os_mbuf_get_pkthdr(&_sdu_mbuf_pool, 0);
    if (!sdu)
        return WBLE_ERR_WANT_WRITE;   // transmits in flight; retry on unstall
    if (os_mbuf_append(sdu, buf, n) != 0) {
        os_mbuf_free_chain(sdu);
        return WBLE_ERR_UNKNOWN;
    }

    int rc = ble_l2cap_send(chan, sdu);
    if (rc == 0) {
        _lock();
        _tx_backoff_count = 0;
        _unlock();
        return (ssize_t)n;
    }

    if (rc == BLE_HS_ESTALLED) {
        // The stack kept the SDU and will finish it as credits arrive, so
        // these bytes ARE written — reporting a short write here would send
        // them twice. It just won't take another one until TX_UNSTALLED.
        _lock();
        _tx_stalled = true;
        _tx_backoff_count = 0;
        _unlock();
        return (ssize_t)n;
    }

    // EBUSY and EBADDATA are the only returns that reject the SDU before the
    // channel adopts it. Every other failure — ENOMEM out of msys while
    // fragmenting, or a transmit that the link layer refused — runs the
    // stack's internal failure path, which frees the SDU itself before
    // returning, so freeing it here would put the block back into
    // _sdu_mempool twice. (ble_l2cap_send documents itself as consuming the
    // mbuf on success only. It does not.)
    if (rc == BLE_HS_EBUSY || rc == BLE_HS_EBADDATA)
        os_mbuf_free_chain(sdu);

    if (rc == BLE_HS_EBUSY) {
        // A previous SDU is still draining; TX_UNSTALLED is the wakeup.
        _lock();
        _tx_stalled = true;
        _unlock();
        return WBLE_ERR_WANT_WRITE;
    }

    if (rc == BLE_HS_ENOMEM) {
        // The host is out of mbufs, which is a queue that has to drain rather
        // than a broken stream: TX_SDU_MAX keeps an SDU to a single fragment,
        // so this send took all of it or none of it, and the stack's failure
        // path took ours with it. Nothing reached the peer, so the same bytes
        // can go again.
        //
        // Nothing will announce that a block came free, either — msys blocks
        // return as the controller acknowledges packets it already holds,
        // which is not a channel event. This is the one shortage L2CAP's
        // credit scheme does not cover, and the hold-off is the flow control
        // standing in for it: can_write() stays false until the timer fires,
        // which keeps the caller's select() asleep instead of spinning on a
        // write that cannot succeed.
        _lock();
        bool exhausted = (++_tx_backoff_count >= TX_BACKOFF_MAX);
        bool arm = !exhausted && !_tx_backoff;
        if (arm)
            _tx_backoff = true;
        _unlock();

        if (!exhausted) {
            if(arm){
                esp_err_t err=esp_timer_start_once(_tx_backoff_timer,TX_BACKOFF_MS*1000);
                if(err!=ESP_OK && err!=ESP_ERR_INVALID_STATE){
                    _lock();_tx_backoff=false;_unlock();
                }
            }
            return WBLE_ERR_WANT_WRITE;
        }

        ESP_LOGE(TAG, "out of host mbufs for %d ms, giving up on the link "
                      "(msys %d/%d mbufs free)",
                 TX_BACKOFF_MAX * TX_BACKOFF_MS,
                 os_msys_num_free(), os_msys_count());
        return WBLE_ERR_UNKNOWN;
    }

    // The mbuf counts are summed over every msys pool, so a partial reading is
    // the informative one: the transmit path only ever draws on the smallest
    // pool, so MSYS_2 sitting untouched while MSYS_1 is empty points at this
    // path rather than at the host at large.
    ESP_LOGE(TAG, "ble_l2cap_send failed: %d (msys %d/%d mbufs free)",
             rc, os_msys_num_free(), os_msys_count());
    return WBLE_ERR_UNKNOWN;
}

bool wble_l2cap_can_read(void)
{
    _lock();
    bool ready = (_ring_len > 0) || _peer_gone;
    _unlock();
    return ready;
}

bool wble_l2cap_can_write(void)
{
    _lock();
    bool ready = (_chan != NULL) && !_tx_stalled && !_tx_backoff;
    _unlock();
    return ready;
}

int wble_l2cap_wakeup_fd(void)
{
    return _wakeup_fd;
}

bool wble_l2cap_wait_readable(TickType_t timeout)
{
    if (wble_l2cap_can_read())
        return true;
    xSemaphoreTake(_rx_sem, timeout);
    return wble_l2cap_can_read();
}

bool wble_l2cap_wait_writable(TickType_t timeout)
{
    if (wble_l2cap_can_write())
        return true;
    xSemaphoreTake(_tx_sem, timeout);
    return wble_l2cap_can_write();
}
