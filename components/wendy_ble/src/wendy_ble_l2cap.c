#include "wendy_ble_l2cap.h"

#include <string.h>
#include <unistd.h>

#include "esp_log.h"
#include "esp_vfs_eventfd.h"
#include "freertos/semphr.h"

#include "host/ble_hs.h"
#include "host/ble_l2cap.h"
#include "os/os_mbuf.h"
#include "os/os_mempool.h"


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


//--- globals ---//

static os_membuf_t          _sdu_mem[OS_MEMPOOL_SIZE(SDU_COUNT, MTU)];
static struct os_mempool    _sdu_mempool;
static struct os_mbuf_pool  _sdu_mbuf_pool;

static SemaphoreHandle_t _mutex;
static SemaphoreHandle_t _session_sem;
static SemaphoreHandle_t _rx_sem;
static SemaphoreHandle_t _tx_sem;
static int _wakeup_fd = -1;

/* Guarded by _mutex. */
static struct ble_l2cap_chan *_chan;
static uint16_t _tx_mtu;
static bool     _tx_stalled;
static bool     _peer_gone;        // channel closed; drain the ring, then EOF
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

/// Hand the stack a fresh receive buffer. Only ever called with at least one
/// MTU free in the ring, so a full SDU always fits when it arrives — that is
/// what turns the ring into the channel's flow control.
static int _arm_recv(struct ble_l2cap_chan *chan)
{
    struct os_mbuf *sdu = os_mbuf_get_pkthdr(&_sdu_mbuf_pool, 0);
    if (!sdu) {
        ESP_LOGE(TAG, "SDU pool exhausted arming receive");
        return BLE_HS_ENOMEM;
    }
    return ble_l2cap_recv_ready(chan, sdu);
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
            bool busy = (_chan != NULL);
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
            if (ble_l2cap_get_chan_info(event->connect.chan, &info) == 0) {
                // An SDU larger than what the peer advertised is rejected
                // outright, so this is a hard bound, not a preference.
                tx_mtu = info.peer_coc_mtu < MTU ? info.peer_coc_mtu : MTU;
            }
            _lock();
            _chan = event->connect.chan;
            _tx_mtu = tx_mtu;
            _tx_stalled = false;
            _peer_gone = false;
            _recv_ready_owed = false;
            _ring_head = 0;
            _ring_len = 0;
            _unlock();
            ESP_LOGI(TAG, "L2CAP channel open (tx mtu %u)", (unsigned)tx_mtu);
            _signal(_session_sem);
            return 0;
        }

        case BLE_L2CAP_EVENT_COC_DISCONNECTED:
            ESP_LOGI(TAG, "L2CAP channel closed");
            _lock();
            _chan = NULL;
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
            if (!room)
                _recv_ready_owed = true;
            _unlock();

            os_mbuf_free_chain(sdu);

            // Withholding the next buffer is the backpressure: the peer runs
            // out of credits until a reader drains the ring.
            if (room)
                _arm_recv(event->receive.chan);

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


//--- public functions ---//

esp_err_t wble_l2cap_init(void)
{
    if (_wakeup_fd >= 0)
        return ESP_OK;

    int rc = os_mempool_init(&_sdu_mempool, SDU_COUNT, MTU, _sdu_mem,
                             "wendy_ble_sdu");
    if (rc != 0) {
        ESP_LOGE(TAG, "os_mempool_init failed: %d", rc);
        return ESP_FAIL;
    }
    rc = os_mbuf_pool_init(&_sdu_mbuf_pool, &_sdu_mempool, MTU, SDU_COUNT);
    if (rc != 0) {
        ESP_LOGE(TAG, "os_mbuf_pool_init failed: %d", rc);
        return ESP_FAIL;
    }

    _mutex       = xSemaphoreCreateMutex();
    _session_sem = xSemaphoreCreateBinary();
    _rx_sem      = xSemaphoreCreateBinary();
    _tx_sem      = xSemaphoreCreateBinary();
    if (!_mutex || !_session_sem || !_rx_sem || !_tx_sem) {
        ESP_LOGE(TAG, "semaphore allocation failed");
        return ESP_ERR_NO_MEM;
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

    rc = ble_l2cap_create_server(CONFIG_WENDY_BLE_PSM, MTU, _l2cap_event, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_l2cap_create_server failed: %d", rc);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "L2CAP server listening on PSM %d (mtu %d)",
             CONFIG_WENDY_BLE_PSM, MTU);
    return ESP_OK;
}

bool wble_l2cap_wait_session(TickType_t timeout)
{
    if (wble_l2cap_session_alive())
        return true;
    xSemaphoreTake(_session_sem, timeout);
    return wble_l2cap_session_alive();
}

bool wble_l2cap_session_alive(void)
{
    _lock();
    bool alive = (_chan != NULL);
    _unlock();
    return alive;
}

void wble_l2cap_end_session(void)
{
    _lock();
    struct ble_l2cap_chan *chan = _chan;
    _chan = NULL;
    _peer_gone = false;
    _tx_stalled = false;
    _recv_ready_owed = false;
    _ring_head = 0;
    _ring_len = 0;
    _unlock();

    if (chan)
        ble_l2cap_disconnect(chan);

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
    bool rearm = _recv_ready_owed && _ring_free() >= MTU && _chan != NULL;
    if (rearm)
        _recv_ready_owed = false;
    struct ble_l2cap_chan *chan = _chan;
    bool gone = _peer_gone;
    _unlock();

    if (rearm)
        _arm_recv(chan);

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
    bool stalled = _tx_stalled;
    size_t n = len < _tx_mtu ? len : _tx_mtu;
    _unlock();

    if (!chan)
        return WBLE_ERR_UNKNOWN;
    if (stalled)
        return WBLE_ERR_WANT_WRITE;

    struct os_mbuf *sdu = os_mbuf_get_pkthdr(&_sdu_mbuf_pool, 0);
    if (!sdu)
        return WBLE_ERR_WANT_WRITE;   // transmits in flight; retry on unstall
    if (os_mbuf_append(sdu, buf, n) != 0) {
        os_mbuf_free_chain(sdu);
        return WBLE_ERR_UNKNOWN;
    }

    int rc = ble_l2cap_send(chan, sdu);
    if (rc == 0)
        return (ssize_t)n;

    if (rc == BLE_HS_ESTALLED) {
        // The stack kept the SDU and will finish it as credits arrive, so
        // these bytes ARE written — reporting a short write here would send
        // them twice. It just won't take another one until TX_UNSTALLED.
        _lock();
        _tx_stalled = true;
        _unlock();
        return (ssize_t)n;
    }

    os_mbuf_free_chain(sdu);   // not consumed on any other return

    if (rc == BLE_HS_EBUSY) {
        // A previous SDU is still draining; TX_UNSTALLED is the wakeup.
        _lock();
        _tx_stalled = true;
        _unlock();
        return WBLE_ERR_WANT_WRITE;
    }

    ESP_LOGE(TAG, "ble_l2cap_send failed: %d", rc);
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
    bool ready = (_chan != NULL) && !_tx_stalled;
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
