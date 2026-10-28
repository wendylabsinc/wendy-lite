/* SPDX-License-Identifier: Apache-2.0
 * Sparse mesh CoCs. All operations on NimBLE channel pointers run on the
 * host event queue. Owners exchange bounded buffers, never channel pointers.
 */
#include "wendy_ble_mesh.h"
#include "wendy_ble_l2cap.h"
#include "wendy_net_alloc.h"
#include "wendy_net_profile.h"
#include "mesh_rx_window.h"
#include "mesh_report_lifetime.h"
#include "mesh_gap_effect.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "host/ble_gap.h"
#include "host/ble_hs.h"
#include "host/ble_l2cap.h"
#include "host/util/util.h"
#include "nimble/ble.h"
#include "nimble/nimble_port.h"
#include "os/os_mbuf.h"
#include "os/os_mempool.h"
#include <stdatomic.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#if defined(CONFIG_BT_DUAL_MODE_ARCH) && CONFIG_BT_DUAL_MODE_ARCH
#include "btdm_osal_freertos.h"
#endif

#ifndef CONFIG_WENDY_NET_BLE_RX_SDU_SLOTS
#define CONFIG_WENDY_NET_BLE_RX_SDU_SLOTS 1
#endif
#define RX_SLOTS CONFIG_WENDY_NET_BLE_RX_SDU_SLOTS
#define MTU (245 * RX_SLOTS)
/* Match WendyOS's stream chunk size. A full write plus the two-byte CoC
 * SDU length and four-byte L2CAP header occupies 246 bytes rather than 251,
 * leaving headroom at the controller's ACL packet boundary. */
#define TX_MAX 240
#ifndef CONFIG_WENDY_NET_BLE_SDU_BUFFERS
#define CONFIG_WENDY_NET_BLE_SDU_BUFFERS 6
#endif
#define SDUS CONFIG_WENDY_NET_BLE_SDU_BUFFERS
#define BLOCK (MTU + BLE_MBUF_MEMBLOCK_OVERHEAD)
#define CHANNELS CONFIG_WENDY_NET_BLE_CHANNELS
/* Match WendyOS's mesh scheduling requests during authentication as well as
 * steady use. Event lengths are controller hints, not airtime guarantees. */
#define INTERVAL_UNITS 36 /* 45 ms, in 1.25 ms units */
#define MAX_CE_UNITS 8    /* 5 ms, in 0.625 ms units */
/* Pinned IDF 6.0.3 timer objects are 32 bytes without profiling and fit within
 * 64 bytes with profiling. The public handle is opaque; reserve that ceiling
 * before creation rather than claiming an exact SDK allocation size. */
#define TIMER_RESERVATION_BYTES 64
/* Both NPL ports wrap a separately pooled/allocated event, but dual-mode
 * targets use the BTDM OSAL backing type rather than NimBLE's FreeRTOS type. */
#if defined(CONFIG_BT_DUAL_MODE_ARCH) && CONFIG_BT_DUAL_MODE_ARCH
#define NPL_EVENT_ALLOCATION_BYTES sizeof(struct btdm_osal_event_freertos)
#else
#define NPL_EVENT_ALLOCATION_BYTES sizeof(struct ble_npl_event_freertos)
#endif
#define PIPE_SDK_BYTES (sizeof(StaticSemaphore_t) + NPL_EVENT_ALLOCATION_BYTES)
#define INIT_SDK_BYTES (sizeof(StaticSemaphore_t) + 4 * NPL_EVENT_ALLOCATION_BYTES + TIMER_RESERVATION_BYTES)
#ifndef CONFIG_WENDY_NET_CONSTRAINED_PROFILE
#define CONFIG_WENDY_NET_CONSTRAINED_PROFILE 0
#endif
static const char *TAG = "wendy_ble_mesh";
struct wble_mesh_pipe
{
    struct ble_l2cap_chan *channel;
    struct ble_npl_event event;
    SemaphoreHandle_t wake;
    wendy_net_memory_reservation_t sdk_memory;
    struct wble_mesh_peer peer;
    uint16_t handle, tx_mtu;
    bool stack, owned, held, connected, closing, posted, again,
        stalled, tx_pending, disconnecting, gap_owned, gap_terminating;
    atomic_bool release_requested;
    uint8_t rx_owed;
#if RX_SLOTS == 2
    struct os_mbuf *reserved_rx;
#endif
    uint8_t ring[2 * MTU], tx[TX_MAX];
    size_t ring_head, ring_size, tx_size;
    unsigned backoffs;
    int64_t retry_at;
    int64_t created;
};
static struct wble_mesh_pipe *pipes[CHANNELS], *pending;
static struct os_mempool pool;
static struct os_mbuf_pool mbufs;
static os_membuf_t *pool_memory;
static SemaphoreHandle_t mutex;
static wendy_net_memory_reservation_t sdk_memory;
static struct ble_npl_event retry_event;
static struct ble_npl_event existing_event;
static struct ble_npl_event control_event;
static struct wble_gap_effect control;
static struct wble_gap_retry init_retry,scan_retry;
static atomic_bool control_init_done,control_stop_ack;
static bool stop_commands_done;
static struct wble_gap_retirement stopping_acls[MYNEWT_VAL(BLE_MAX_CONNECTIONS)];
static struct ble_npl_event dial_timeout_event;
static uint16_t existing_handle;
static uint32_t dial_epoch, existing_epoch;
static int64_t dial_until;
static int64_t scan_dial_after;
static bool dial_timeout_posted, dial_gap_pending;
static esp_timer_handle_t retry_timer;
static atomic_bool ready, starting;
static atomic_bool quiescing;
static atomic_bool router_accepting=true;
static atomic_uint router_capacity_refusals;
static bool timer_running, scan_paused, dialing, scan_owned;
/* Capacity affects discovery only; an already queued dial remains valid. */
static atomic_bool scan_interest=true, scan_listen_pending;
static uint8_t own_type;
static uint16_t dial_psm;
static wble_mesh_report report;
static void *report_context;
static struct wble_report_lifetime report_lifetime;
static struct wble_report_lifetime timer_lifetime;
static void pipe_event(struct ble_npl_event *);
static int coc_event(struct ble_l2cap_event *, void *);
static int start_scan(void);
static void lock(void) { xSemaphoreTake(mutex, portMAX_DELAY); }
static bool trylock(void) { return xSemaphoreTake(mutex,0)==pdTRUE; }
static void unlock(void) { xSemaphoreGive(mutex); }
static void control_run(struct ble_npl_event *);
static bool stop_resources(void);
static _Atomic(void (*)(void)) actor_wakeup;
static void wake_actor(void){void (*wake)(void)=atomic_load(&actor_wakeup);if(wake)wake();}
static void terminate_unclaimed(uint16_t handle)
{
    /* Only new mesh-created ACLs arriving during OFF enter this host-owned
     * table. Existing management ACLs never enter it. Its size is the SDK's
     * physical connection ceiling, so every live connection has a slot. */
    struct wble_gap_retirement *entry=atomic_load(&quiescing) ?
        wble_gap_retiring_add(stopping_acls,MYNEWT_VAL(BLE_MAX_CONNECTIONS),handle):NULL;
    int rc=ble_gap_terminate(handle,BLE_ERR_REM_USER_CONN_TERM);
    if(entry){
        if(rc==BLE_HS_ENOTCONN)entry->used=false;
        else entry->sent=!rc || rc==BLE_HS_EALREADY;
    }
}
void wble_mesh_set_wakeup(void (*wake)(void)){atomic_store(&actor_wakeup,wake);}
static void notify(struct wble_mesh_pipe *p) { xSemaphoreGive(p->wake);void (*wake)(void)=atomic_load(&actor_wakeup);if(wake)wake(); }
static void post(struct wble_mesh_pipe *p)
{
    if (p->posted)
    {
        p->again = true;
        return;
    }
    p->posted = true;
    ble_npl_eventq_put(nimble_port_get_dflt_eventq(), &p->event);
}
static unsigned count(void)
{
    unsigned n = 0;
    for (unsigned i = 0; i < CHANNELS; i++)
        n += pipes[i] != NULL;
    return n;
}
static struct wble_mesh_pipe *find(struct ble_l2cap_chan *channel)
{
    if (!channel)
        return NULL;
    for (unsigned i = 0; i < CHANNELS; i++)
        if (pipes[i] && pipes[i]->channel == channel)
            return pipes[i];
    return NULL;
}
static void release_reserved_receive(struct wble_mesh_pipe *p)
{
#if RX_SLOTS == 2
    os_mbuf_free_chain(p->reserved_rx);p->reserved_rx=NULL;
#else
    (void)p;
#endif
}
static void retire(struct wble_mesh_pipe *p)
{
    if (p->stack || p->owned || p->posted || p->held || p->gap_owned)
        return;
    for (unsigned i = 0; i < CHANNELS; i++)
        if (pipes[i] == p)
            pipes[i] = NULL;
    if (pending == p)
        pending = NULL;
    /* ESP-IDF's NPL event_init owns a separate event-pool entry. The
     * posted/held checks above ensure no queued callback can still use it. */
    ble_npl_event_deinit(&p->event);
    release_reserved_receive(p);
    vSemaphoreDelete(p->wake);
    wendy_net_memory_release(&p->sdk_memory);
    wendy_net_free(p);
    /* A released private slot changes time-service availability even if no
     * carrier packet follows. Wake the existing actor to refresh its hint. */
    void (*wake)(void)=atomic_load(&actor_wakeup);if(wake)wake();
}
static void reap_pool(void)
{
    if (!count() && pool_memory && pool.mp_num_free == SDUS)
    {
        wendy_net_free(pool_memory);
        pool_memory = NULL;
        ESP_LOGI(TAG, "idle mesh SDU pool released");
    }
    if (!count() && !pool_memory && timer_running)
    {
        esp_timer_stop(retry_timer);
        timer_running = false;
    }
}
static int ensure_pool(void)
{
    if (pool_memory)
        return 0;
    /* NimBLE mbufs and host queue state retain strict internal placement;
     * their owner and bytes still belong to the common runtime ceiling. */
    /* SDUs belong to the host L2CAP task, not controller DMA. IDF's supported
     * external NimBLE host allocator permits the same mbuf storage in PSRAM.
     * Keep pipe/semaphore/event control state internal; the ordinary mesh
     * allocator selects PSRAM when present and internal RAM otherwise. */
    pool_memory = wendy_net_calloc(OS_MEMPOOL_SIZE(SDUS, BLOCK), sizeof *pool_memory);
    if (!pool_memory)
        return -1;
    if (os_mempool_init(&pool, SDUS, BLOCK, pool_memory, "net-coc") ||
        os_mbuf_pool_init(&mbufs, &pool, BLOCK, SDUS))
    {
        wendy_net_free(pool_memory);
        pool_memory = NULL;
        return -1;
    }
    return 0;
}
static struct wble_mesh_pipe *make_pipe(struct ble_l2cap_chan *channel,
                                        uint16_t handle, bool server, uint16_t psm)
{
    unsigned slot;
    for (slot = 0; slot < CHANNELS; slot++)
        if (!pipes[slot])
            break;
    if (slot == CHANNELS)
        return NULL;
    for (unsigned i = 0; i < CHANNELS; i++)
        if (pipes[i] && pipes[i]->stack && pipes[i]->handle == handle)
            return NULL;
    struct wble_mesh_pipe *p = wendy_net_internal_calloc(1, sizeof *p);
    if (!p)
        return NULL;
    atomic_init(&p->release_requested,false);
    /* IDF FreeRTOS queues/semaphores allocate internal memory. NPL event
     * entries come from the shared SDK event pool (or its internal heap
     * fallback). Reserve their exclusively occupied bytes before creation;
     * do not charge the entire shared host/controller pool to mesh. */
    if(!wendy_net_memory_reserve(wendy_net_runtime_memory_ledger(),&p->sdk_memory,
                                 PIPE_SDK_BYTES,WENDY_NET_MEMORY_INTERNAL)){
        wendy_net_free(p);return NULL;
    }
    p->wake = xSemaphoreCreateBinary();
    if (!p->wake || ensure_pool())
    {
        if (p->wake)
            vSemaphoreDelete(p->wake);
        wendy_net_memory_release(&p->sdk_memory);
        wendy_net_free(p);
        return NULL;
    }
    p->channel = channel;
    p->handle = handle;
    p->stack = true;
    p->peer.server = server;
    p->peer.psm = psm;
    p->tx_mtu = MTU;
    p->rx_owed = RX_SLOTS;
    p->created = esp_timer_get_time();
    ble_npl_event_init(&p->event, pipe_event, p);
    if (!timer_running)
    {
        if (esp_timer_start_periodic(retry_timer, 10000) != ESP_OK)
        {
            ble_npl_event_deinit(&p->event);
            vSemaphoreDelete(p->wake);
            wendy_net_memory_release(&p->sdk_memory);
            wendy_net_free(p);
            reap_pool();
            return NULL;
        }
        timer_running = true;
    }
    pipes[slot] = p;
    return p;
}
static void close_pipe(struct wble_mesh_pipe *p)
{
    p->closing = true;
    notify(p);
    post(p);
}
static void receive_data_locked(struct wble_mesh_pipe *p,struct os_mbuf *sdu)
{
    size_t n=OS_MBUF_PKTLEN(sdu),tail=(p->ring_head+p->ring_size)%sizeof p->ring;
    size_t first=sizeof p->ring-tail;if(first>n)first=n;
    if(n>MTU || n>sizeof p->ring-p->ring_size ||
       os_mbuf_copydata(sdu,0,first,p->ring+tail) ||
       (n>first && os_mbuf_copydata(sdu,first,n-first,p->ring))){
        ESP_LOGW(TAG,"mesh receive rejected: handle=%u bytes=%u room=%u",
            p->handle,(unsigned)n,(unsigned)(sizeof p->ring-p->ring_size));
        close_pipe(p);
    }else{
        p->ring_size+=n;
        if(p->rx_owed<RX_SLOTS)p->rx_owed++;
        else close_pipe(p);
        notify(p);post(p);
    }
}
/* Host-thread-only. The private block includes mbuf and packet-header space,
 * so a complete advertised MTU fits without chaining another block. */
static int submit_receive(struct wble_mesh_pipe *p,struct os_mbuf *sdu)
{
    int result = ble_l2cap_recv_ready(p->channel, sdu);
    /* The pinned NimBLE assigns the SDU before its ENOENT check. EBUSY
     * rejects it before assignment; other errors have consumed it. */
    if (result == BLE_HS_EBUSY)
        os_mbuf_free_chain(sdu);
    if(!result){lock();if(p->rx_owed)p->rx_owed--;unlock();}
    return result;
}
/* Preallocate the complete batch before the first SDK call can publish a
 * credit. ENOMEM transfers none; SDK rejections free every unsubmitted block. */
static int arm_receive_batch(struct wble_mesh_pipe *p,unsigned count)
{
    if(!count || count>RX_SLOTS)return BLE_HS_EINVAL;
    struct os_mbuf *buffers[RX_SLOTS]={0};
    for(unsigned i=0;i<count;i++){
        buffers[i]=os_mbuf_get_pkthdr(&mbufs,0);
        if(!buffers[i]){for(unsigned j=0;j<i;j++)os_mbuf_free_chain(buffers[j]);return BLE_HS_ENOMEM;}
    }
    for(unsigned i=0;i<count;i++){
        int result=submit_receive(p,buffers[i]);
        if(result){for(unsigned j=i+1;j<count;j++)os_mbuf_free_chain(buffers[j]);return result;}
    }
    return 0;
}
static struct os_mbuf *reserve_initial_receive(struct wble_mesh_pipe *p)
{
    struct os_mbuf *first=os_mbuf_get_pkthdr(&mbufs,0);if(!first)return NULL;
#if RX_SLOTS == 2
    p->reserved_rx=os_mbuf_get_pkthdr(&mbufs,0);
    if(!p->reserved_rx){os_mbuf_free_chain(first);return NULL;}
#endif
    /* First is transferred to ble_l2cap_connect; the spare remains ours until
     * CONNECTED synchronously arms it before the host processes peer data. */
    p->rx_owed=RX_SLOTS-1;return first;
}
static void pipe_event(struct ble_npl_event *event)
{
    struct wble_mesh_pipe *p = ble_npl_event_get_arg(event);
    lock();
    p->again = false;
    struct ble_l2cap_chan *channel = p->channel;
    bool close = p->closing && channel && !p->disconnecting &&
                 esp_timer_get_time() >= p->retry_at;
    if (close)
        p->disconnecting = true;
    unsigned arm = channel && p->connected && !p->closing ?
        wble_rx_rearm_budget(RX_SLOTS,p->rx_owed,sizeof p->ring-p->ring_size,MTU):0;
    bool send = channel && p->connected && !p->closing && p->tx_pending &&
                !p->stalled && esp_timer_get_time() >= p->retry_at;
    bool release_gap = p->gap_owned && !p->stack && !channel &&
                       !p->gap_terminating && esp_timer_get_time() >= p->retry_at;
    unlock();
    if (release_gap)
    {
        /* Run on the host queue: a management CoC cannot be accepted between
         * this ownership check and the terminate request. Borrowed incoming
         * or existing ACLs never acquire gap_owned. A shared management ACL
         * transfers to the management host rather than dying with mesh. */
        bool shared = wble_l2cap_uses_connection(p->handle);
        int rc = shared ? 0 : ble_gap_terminate(p->handle, BLE_ERR_REM_USER_CONN_TERM);
        lock();
        if (shared || rc == BLE_HS_ENOTCONN)
            p->gap_owned = false;
        else if (!rc || rc == BLE_HS_EALREADY)
            p->gap_terminating = true;
        else
            p->retry_at = esp_timer_get_time() + 10000;
        unlock();
    }
    if (close)
    {
        int rc = ble_l2cap_disconnect(channel);
        if (rc)
        {
            lock();
            p->disconnecting = false;
            p->retry_at = esp_timer_get_time() + 10000;
            if (rc == BLE_HS_ENOTCONN)
            {
                p->channel = NULL;
                p->connected = p->stack = false;
                notify(p);
            }
            unlock();
        }
    }
    else
    {
        if (arm)
        {
            int rc = arm_receive_batch(p,arm);
            lock();
            if (rc && rc != BLE_HS_ENOMEM){
                ESP_LOGW(TAG,"mesh receive rearm failed: handle=%u result=%d",p->handle,rc);
                close_pipe(p);
            }
            unlock();
        }
        if (send)
        {
            lock();
            send = p->channel == channel && p->connected && !p->closing;
            unlock();
        }
        if (send)
        {
            struct os_mbuf *sdu = os_mbuf_get_pkthdr(&mbufs, 0);
            int rc = BLE_HS_ENOMEM;
            if (sdu)
            {
                if (os_mbuf_append(sdu, p->tx, p->tx_size))
                {
                    os_mbuf_free_chain(sdu);
                    sdu = NULL;
                }
                else
                    rc = ble_l2cap_send(channel, sdu);
            }
            /* NimBLE consumes SDUs on success, ESTALLED and most errors.
             * Only EBUSY/EBADDATA reject them before taking ownership. */
            if (sdu && (rc == BLE_HS_EBUSY || rc == BLE_HS_EBADDATA))
                os_mbuf_free_chain(sdu);
            lock();
            if (!rc || rc == BLE_HS_ESTALLED)
            {
                p->tx_pending = false;
                p->stalled = rc == BLE_HS_ESTALLED;
                p->backoffs = 0;
                notify(p);
            }
            else if (rc == BLE_HS_EBUSY)
                p->stalled = true;
            else if (rc == BLE_HS_ENOMEM){
                /* Keep this one bounded stream write pending. Shared mbuf
                 * pressure is backpressure, not a two-second link lifetime.
                 * The owning TLS/carrier deadline and GAP supervision still
                 * close a link that cannot make progress. */
                if(p->backoffs<UINT_MAX)p->backoffs++;
                p->retry_at = esp_timer_get_time() + 10000;
            }
            else{
                ESP_LOGW(TAG,"mesh send failed: handle=%u result=%d backoffs=%u",
                    p->handle,rc,p->backoffs);
                close_pipe(p);
            }
            unlock();
        }
    }
    lock();
    p->posted = false;
    if (p->again && p->stack)
        post(p);
    retire(p);
    reap_pool();
    unlock();
}
static void retry(struct ble_npl_event *event)
{
    (void)event;
    lock();
    for (unsigned i = 0; i < CHANNELS; i++)
    {
        struct wble_mesh_pipe *p = pipes[i];
        if(p && atomic_exchange(&p->release_requested,false)){p->owned=false;close_pipe(p);}
        if (p && p->connected && !p->owned &&
            esp_timer_get_time() - p->created >= INT64_C(10000000))
            close_pipe(p);
        bool gap_cleanup = p && p->gap_owned && !p->stack &&
                           !p->gap_terminating && esp_timer_get_time() >= p->retry_at;
        bool channel_work = p && p->stack &&
                            (p->closing || (p->connected && p->channel &&
                              wble_rx_rearm_budget(RX_SLOTS,p->rx_owed,sizeof p->ring-p->ring_size,MTU)) ||
                             (p->tx_pending && !p->stalled &&
                              esp_timer_get_time() >= p->retry_at));
        if (gap_cleanup || channel_work)
            post(p);
    }
    reap_pool();
    unlock();
}
static void timer(void *context)
{
    (void)context;
    if(!wble_report_acquire(&timer_lifetime))return;
    ble_npl_eventq_put(nimble_port_get_dflt_eventq(), &retry_event);
    wble_report_release(&timer_lifetime);
}
static int coc_event(struct ble_l2cap_event *event, void *context)
{
    if (!atomic_load(&ready))
        return BLE_HS_EBUSY;
    if (event->type == BLE_L2CAP_EVENT_COC_ACCEPT)
    {
        if(WENDY_NET_NON_TRANSIT || atomic_load(&quiescing))return BLE_HS_EBUSY;
        if ((uint16_t)(uintptr_t)context != WBLE_MESH_TIME_PSM &&
            !atomic_load(&router_accepting))
        {
            unsigned count=atomic_fetch_add(&router_capacity_refusals,1)+1;
            (void)count;
            return BLE_HS_EBUSY;
        }
        lock();
        struct wble_mesh_pipe *p =
            make_pipe(event->accept.chan, event->accept.conn_handle, true,
                      (uint16_t)(uintptr_t)context);
        if (p)
            p->held = true;
        unlock();
        if (!p)
            return BLE_HS_ENOMEM;
        int rc = arm_receive_batch(p,RX_SLOTS);
        lock();
        p->held = false;
        if (rc)
        {
            p->stack = false;
            p->channel = NULL;
            retire(p);
            reap_pool();
        }
        unlock();
        return rc;
    }
    if (event->type == BLE_L2CAP_EVENT_COC_CONNECTED)
    {
        struct ble_gap_conn_desc desc;
        struct ble_l2cap_chan_info info;
        bool info_ok = !event->connect.status &&
                       !ble_gap_conn_find(event->connect.conn_handle, &desc) &&
                       !ble_l2cap_get_chan_info(event->connect.chan, &info);
        if(info_ok){
            int dle=ble_gap_set_data_len(event->connect.conn_handle,251,2120);
            if(dle)ESP_LOGD(TAG,"data length request: %d",dle);
        }
        /* The pre-reserved outgoing spare must be lent before this callback
         * returns to the host receive loop. Initial credits already equal2. */
#if RX_SLOTS == 2
        lock();
        struct wble_mesh_pipe *outgoing=info_ok && context && pending &&
            pending->handle==event->connect.conn_handle ? pending:NULL;
        struct os_mbuf *spare=outgoing ? outgoing->reserved_rx:NULL;
        bool receive_failed=outgoing && !spare;
        if(spare){
            outgoing->channel=event->connect.chan;
            outgoing->held=true;outgoing->reserved_rx=NULL;
        }
        unlock();
        if(spare && submit_receive(outgoing,spare))receive_failed=true;
#endif
        lock();
#if RX_SLOTS == 2
        if(spare)outgoing->held=false;
#endif
        struct wble_mesh_pipe *p = find(event->connect.chan);
        if (!p && context && pending &&
            pending->handle == event->connect.conn_handle)
        {
            p = pending;
            pending = NULL;
        }
        if(p && context && p==pending)pending=NULL;
        if (p)
        {
            if (!info_ok)
            {
                release_reserved_receive(p);
                p->channel = NULL;
                p->stack = p->connected = false;
                notify(p);
                retire(p);
            }
            else
            {
                p->channel = event->connect.chan;
                p->connected = true;
                p->tx_mtu = info.peer_coc_mtu;
                /* A retry must not replay an already transmitted SDU prefix.
                 * Fit the entire stream chunk and two-byte SDU length in one
                 * peer CoC PDU, including peers with a smaller receive MPS. */
                if(info.peer_l2cap_mtu>2 && p->tx_mtu>info.peer_l2cap_mtu-2)
                    p->tx_mtu=info.peer_l2cap_mtu-2;
                p->peer.address_type = desc.peer_ota_addr.type;
                memcpy(p->peer.address, desc.peer_ota_addr.val, 6);
#if RX_SLOTS == 2
                if(receive_failed){
                    ESP_LOGW(TAG,"mesh initial RX window failed: handle=%u",p->handle);
                    p->closing=true;
                }
#endif
                if (p->closing)
                    post(p);
                notify(p);
                ESP_LOGI(
                    TAG,
                    "mesh CoC ready: handle=%u PSM=%u server=%u tx_chunk=%u peer_mps=%u channels=%u interval_us=%u latency=%u timeout_ms=%u",
                    p->handle,p->peer.psm,(unsigned)p->peer.server,
                    p->tx_mtu<TX_MAX ? p->tx_mtu:TX_MAX,info.peer_l2cap_mtu,count(),
                    (unsigned)desc.conn_itvl*1250,(unsigned)desc.conn_latency,
                    (unsigned)desc.supervision_timeout*10);
            }
        }
        reap_pool();
        unlock();
        return 0;
    }
    struct ble_l2cap_chan *channel =
        event->type == BLE_L2CAP_EVENT_COC_DISCONNECTED ? event->disconnect.chan
        : event->type == BLE_L2CAP_EVENT_COC_DATA_RECEIVED ? event->receive.chan
        : event->type == BLE_L2CAP_EVENT_COC_TX_UNSTALLED
            ? event->tx_unstalled.chan
            : NULL;
    lock();
    struct wble_mesh_pipe *p = find(channel);
    if (event->type == BLE_L2CAP_EVENT_COC_DATA_RECEIVED)
    {
        struct os_mbuf *sdu = event->receive.sdu_rx;
        if (p && sdu && p->connected && !p->closing)
            receive_data_locked(p,sdu);
        unlock();
        if (sdu)
            os_mbuf_free_chain(sdu);
        return 0;
    }
    if (p && event->type == BLE_L2CAP_EVENT_COC_DISCONNECTED)
    {
        p->channel = NULL;
        p->stack = p->connected = false;
        p->tx_pending = false;
        p->rx_owed = false;
        notify(p);
        if(p->gap_owned)post(p);
        retire(p);
        reap_pool();
    }
    else if (p && event->type == BLE_L2CAP_EVENT_COC_TX_UNSTALLED)
    {
        if (event->tx_unstalled.status==BLE_HS_ENOMEM){
            /* No prefix can have gone out: each SDU fits one peer PDU.
             * While stalled the producer cannot replace this retained chunk. */
            p->stalled=false;p->tx_pending=true;
            p->retry_at=esp_timer_get_time()+10000;
            post(p);notify(p);
        }
        else if (event->tx_unstalled.status)
            close_pipe(p);
        else
        {
            p->stalled = false;
            notify(p);
            if (p->tx_pending)
                post(p);
        }
    }
    unlock();
    return 0;
}

static int gap_event(struct ble_gap_event *event, void *context)
{
    if(!atomic_load(&ready))return 0;
    if (event->type == BLE_GAP_EVENT_DISCONNECT)
    {
        wble_gap_retiring_done(stopping_acls,MYNEWT_VAL(BLE_MAX_CONNECTIONS),event->disconnect.conn.conn_handle);
        lock();
        for(unsigned i=0;i<CHANNELS;i++){
            struct wble_mesh_pipe *p=pipes[i];
            if(p && p->gap_owned && p->handle==event->disconnect.conn.conn_handle){
                p->gap_owned=false;p->gap_terminating=false;
                notify(p);retire(p);
            }
        }
        reap_pool();unlock();
    }
    else if (event->type == BLE_GAP_EVENT_DISC)
    {
        lock();
        wble_mesh_report callback = report;
        void *ctx = report_context;
        bool borrowed = callback && wble_report_acquire(&report_lifetime);
        unlock();
        if (borrowed) {
            callback(ctx, event->disc.addr.val, event->disc.addr.type,
                     event->disc.data, event->disc.length_data,
                     event->disc.rssi);
            wble_report_release(&report_lifetime);
        }
    }
    else if (event->type == BLE_GAP_EVENT_DISC_COMPLETE)
    {
        lock();
        scan_owned = false;
        bool resume = !scan_paused && report && atomic_load(&scan_interest);
        unlock();
        if (resume)
            start_scan();
    }
    else if (event->type == BLE_GAP_EVENT_CONNECT)
    {
        uint16_t handle = event->connect.conn_handle;
        if(atomic_load(&quiescing)){
            lock();dialing=false;dial_gap_pending=false;unlock();
            if(!event->connect.status && !context)terminate_unclaimed(handle);
            return 0;
        }
        lock();
        dialing = false;
        dial_gap_pending = false;
        scan_paused = false;
        struct wble_mesh_pipe *p =
            event->connect.status ? NULL : make_pipe(NULL, handle, false, dial_psm);
        if (p)
        {
            p->held = true;
            p->gap_owned = context == NULL;
            pending = p;
        }
        uint16_t psm = dial_psm;
        unlock();
        if (p)
        {
            struct os_mbuf *sdu = reserve_initial_receive(p);
            int rc = sdu ? ble_l2cap_connect(handle, psm, MTU, sdu, coc_event,
                                             (void *)1)
                         : BLE_HS_ENOMEM;
            lock();
            p->held = false;
            if (rc)
            {
                release_reserved_receive(p);
                p->stack = false;
                p->connected = false;
                p->channel = NULL;
                if (pending == p)
                    pending = NULL;
                notify(p);
            }
            retire(p);
            reap_pool();
            unlock();
            if (rc)
                ESP_LOGW(TAG, "mesh CoC dial failed: %d", rc);
        }
        else if (!event->connect.status && !context)
        {
            /* A new outgoing GAP connection with no channel has no owner. */
            ble_gap_terminate(handle, BLE_ERR_REM_USER_CONN_TERM);
        }
        start_scan();
    }
    return 0;
}
static int dial_gap_event(struct ble_gap_event *event, void *context)
{
    if(!atomic_load(&ready)){
        if(event->type==BLE_GAP_EVENT_CONNECT && !event->connect.status)
            ble_gap_terminate(event->connect.conn_handle,BLE_ERR_REM_USER_CONN_TERM);
        return 0;
    }
    if (event->type == BLE_GAP_EVENT_CONNECT) {
        lock();
        bool current = dialing && (uint32_t)(uintptr_t)context == dial_epoch;
        unlock();
        if (!current) {
            if (!event->connect.status)
                terminate_unclaimed(event->connect.conn_handle);
            lock();
            bool resume = !dialing && !scan_paused;
            unlock();
            if (resume)
                start_scan();
            return 0;
        }
    }
    return gap_event(event, NULL);
}
static void dial_timeout(struct ble_npl_event *unused)
{
    (void)unused;
    lock();
    bool expired = dialing && esp_timer_get_time() >= dial_until;
    bool cancel = expired && dial_gap_pending;
    if (expired) {
        ++dial_epoch;
        dialing = false;
        dial_gap_pending = false;
        scan_paused = false;
    }
    dial_timeout_posted = false;
    unlock();
    if (expired) {
        int rc = cancel ? ble_gap_conn_cancel() : 0;
        ESP_LOGW(TAG, "mesh GAP dial exceeded 20s; resuming candidate discovery: cancel=%d", rc);
        start_scan();
    }
}
static void open_existing(struct ble_npl_event *unused)
{
    (void)unused;
    struct ble_gap_event event = {0};
    event.type = BLE_GAP_EVENT_CONNECT;
    lock();
    bool current = dialing && existing_epoch == dial_epoch;
    event.connect.conn_handle = existing_handle;
    unlock();
    if (current)
        (void)gap_event(&event, (void *)1);
}
static int start_scan(void)
{
    if (!atomic_load(&ready) || atomic_load(&quiescing))
        return BLE_HS_ENOTSYNCED;
    if(!wble_gap_retry_due(&scan_retry,esp_timer_get_time()))return 0;
    lock();
    bool wanted = report && !scan_paused && atomic_load(&scan_interest);
    bool ours=scan_owned;
    unlock();
    if(!wanted){
        /* Only the host performs cancellation, and only for our discovery.
         * Management/shared discovery never transfers ownership to us. */
        int rc=ours && ble_gap_disc_active() ? ble_gap_disc_cancel():0;
        if(rc && rc!=BLE_HS_EALREADY){
            wble_gap_retry_failed(&scan_retry,esp_timer_get_time());return rc;
        }
        lock();scan_owned=false;unlock();
        if(ours && !atomic_load(&scan_interest))
            ESP_LOGI(TAG,"mesh discovery paused: authenticated carrier capacity full");
        return 0;
    }
    if(ble_gap_disc_active()){
        if(ours){atomic_store(&scan_listen_pending,false);return 0;}
        /* Normal shared-host contention must not masquerade as our scan. */
        if(!atomic_load(&quiescing))wble_gap_retry_failed(&scan_retry,esp_timer_get_time());
        return BLE_HS_EBUSY;
    }
    struct ble_gap_disc_params params = {
        .passive = 1, .filter_duplicates = 0, .itvl = 160, .window = 48};
    int rc = ble_gap_disc(own_type, BLE_HS_FOREVER, &params, gap_event, NULL);
    /* A competing baseline caller can start discovery between our active
     * check and this command. EALREADY did not transfer its callback to us. */
    if(rc==BLE_HS_EALREADY)rc=BLE_HS_EBUSY;
    bool resumed=false;
    lock();
    if (!rc) {
        wble_gap_retry_clear(&scan_retry);
        scan_owned = true;
        resumed=atomic_exchange(&scan_listen_pending,false);
        /* A failed dial must not immediately monopolise the radio again.
         * Leave time to hear slower advertisers and discover alternatives. */
        scan_dial_after = esp_timer_get_time() + INT64_C(2000000);
    }
    unlock();
    if(resumed)ESP_LOGI(TAG,"mesh discovery resumed: carrier slot available");
    if(rc && !atomic_load(&quiescing))wble_gap_retry_failed(&scan_retry,esp_timer_get_time());
    if (rc && rc != BLE_HS_EALREADY)
        ESP_LOGW(TAG, "mesh scan start failed: %d", rc);
    return rc==BLE_HS_EALREADY ? 0:rc;
}
void wble_mesh_router_admission(bool available)
{
    atomic_store(&router_accepting,available && !WENDY_NET_NON_TRANSIT);
}
bool wble_mesh_incoming_available(void)
{
    if(WENDY_NET_NON_TRANSIT || !atomic_load(&ready) || atomic_load(&quiescing) || !mutex)
        return false;
    /* This is an outer-actor readiness peek, never a wait for host I/O. A
     * contended snapshot is temporarily unavailable and retried next turn. */
    if(xSemaphoreTake(mutex,0)!=pdTRUE)return false;
    bool available=!pending && count()+(dialing ? 1:0)<CHANNELS;
    xSemaphoreGive(mutex);return available;
}

esp_err_t wble_mesh_init(void)
{
    if (atomic_load(&ready))
        return ESP_OK;
    if(!atomic_load(&starting) && !wble_gap_retry_due(&init_retry,esp_timer_get_time()))
        return ESP_ERR_INVALID_STATE;
    if (!ble_hs_synced())
        return ESP_ERR_INVALID_STATE;
    /* Default one-slot MTU fits one MPS. The explicit two-slot experiment
     * owns both full buffers before remote initial credits can be consumed. */
    if(MYNEWT_VAL(BLE_L2CAP_COC_MPS)<245 ||
       (RX_SLOTS==2 && (MYNEWT_VAL(BLE_L2CAP_COC_MPS)!=248 || MYNEWT_VAL(BLE_L2CAP_COC_SDU_BUFF_COUNT)!=2 ||
                       SDUS<(RX_SLOTS+1)*CHANNELS+1))){
        wble_gap_retry_failed(&init_retry,esp_timer_get_time());
        ESP_LOGE(TAG,"native BLE receive profile invalid: slots=%u MTU=%u MPS=%u SDK_slots=%u SDUs=%u channels=%u",
            (unsigned)RX_SLOTS,(unsigned)MTU,(unsigned)MYNEWT_VAL(BLE_L2CAP_COC_MPS),
            (unsigned)MYNEWT_VAL(BLE_L2CAP_COC_SDU_BUFF_COUNT),(unsigned)SDUS,(unsigned)CHANNELS);
        return ESP_ERR_INVALID_STATE;
    }
    if (atomic_exchange(&starting, true)){
        if(atomic_load(&control_init_done) && !atomic_load(&ready)) (void)stop_resources();
        else if(atomic_load(&control.pending))
            ble_npl_eventq_put(nimble_port_get_dflt_eventq(),&control_event);
        return ESP_ERR_INVALID_STATE;
    }
    atomic_store(&quiescing,false);
    atomic_store(&scan_interest,true);atomic_store(&scan_listen_pending,false);
    esp_err_t result = ESP_FAIL;
    if (CONFIG_WENDY_NET_BLE_PSM == CONFIG_WENDY_BLE_PSM ||
        CONFIG_WENDY_NET_BLE_PSM == WBLE_MESH_TIME_PSM ||
        CONFIG_WENDY_BLE_PSM == WBLE_MESH_TIME_PSM)
        goto fail;
    if(!wendy_net_memory_reserve(wendy_net_runtime_memory_ledger(),&sdk_memory,
                                 INIT_SDK_BYTES,WENDY_NET_MEMORY_INTERNAL)){
        result=ESP_ERR_NO_MEM;goto fail;
    }
    mutex = xSemaphoreCreateMutex();
    if (!mutex)
    {
        result = ESP_ERR_NO_MEM;
        goto fail;
    }
    ble_npl_event_init(&retry_event, retry, NULL);
    ble_npl_event_init(&existing_event, open_existing, NULL);
    ble_npl_event_init(&dial_timeout_event, dial_timeout, NULL);
    ble_npl_event_init(&control_event,control_run,NULL);
    wble_gap_effect_init(&control);
    atomic_store(&control_init_done,false);atomic_store(&control_stop_ack,false);
    stop_commands_done=false;wble_report_open(&timer_lifetime);
    memset(stopping_acls,0,sizeof stopping_acls);
    const esp_timer_create_args_t args = {.callback = timer,
                                          .name = "net-coc-retry"};
    result = esp_timer_create(&args, &retry_timer);
    if (result != ESP_OK)
        goto fail;
    atomic_store(&quiescing,false);
    if(!wble_gap_submit(&control,WBLE_GAP_INIT,NULL))goto fail;
    ble_npl_eventq_put(nimble_port_get_dflt_eventq(),&control_event);
    return ESP_ERR_INVALID_STATE; /* Host completion is collected next loop. */
fail:
    if(!atomic_load(&quiescing))wble_gap_retry_failed(&init_retry,esp_timer_get_time());
    if (retry_timer){esp_timer_delete(retry_timer);retry_timer=NULL;}
    if (mutex){vSemaphoreDelete(mutex);mutex=NULL;}
    ble_npl_event_deinit(&retry_event);ble_npl_event_deinit(&existing_event);
    ble_npl_event_deinit(&dial_timeout_event);ble_npl_event_deinit(&control_event);
    wendy_net_memory_release(&sdk_memory);atomic_store(&starting,false);
    return result==ESP_OK ? ESP_FAIL:result;
}
static int initialize_host(void)
{
    if (ble_hs_id_infer_auto(0, &own_type))
        return ESP_FAIL;
    if(!WENDY_NET_NON_TRANSIT){
        int rc=ble_l2cap_create_server(WBLE_MESH_TIME_PSM,MTU,coc_event,
                                      (void *)(uintptr_t)WBLE_MESH_TIME_PSM);
        if(rc && rc!=BLE_HS_EALREADY){
            ESP_LOGW(TAG,"timestamp HTTPS PSM%u registration failed: %d",WBLE_MESH_TIME_PSM,rc);
            return ESP_FAIL;
        }
        rc=ble_l2cap_create_server(CONFIG_WENDY_NET_BLE_PSM,MTU,coc_event,
                                  (void *)(uintptr_t)CONFIG_WENDY_NET_BLE_PSM);
        if(rc && rc!=BLE_HS_EALREADY)return ESP_FAIL;
    }
    if(atomic_load(&quiescing))return BLE_HS_EALREADY;
    wble_report_open(&report_lifetime);
    atomic_store(&router_accepting,!WENDY_NET_NON_TRANSIT);
    atomic_store(&ready, true);
    ESP_LOGI(TAG,"mesh BLE mode=%s; peer PSM=%u time PSM=%u channel cap=%u MTU=%u; buffers allocated on demand",
        WENDY_NET_NON_TRANSIT ? "scan/dial only":"scan/dial/listen",
        CONFIG_WENDY_NET_BLE_PSM,WBLE_MESH_TIME_PSM,CHANNELS,MTU);
    ESP_LOGI(TAG,"mesh BLE profile: GAP=%u CoC=%u SDUs=%u pool_bytes=%u MPS=%u initial_credits=%u rx_slots=%u central_interval_us=%u max_ce_us=%u",
        (unsigned)MYNEWT_VAL(BLE_MAX_CONNECTIONS),(unsigned)MYNEWT_VAL(BLE_L2CAP_COC_MAX_NUM),
        (unsigned)SDUS,(unsigned)(OS_MEMPOOL_SIZE(SDUS,BLOCK)*sizeof *pool_memory),
        (unsigned)MYNEWT_VAL(BLE_L2CAP_COC_MPS),
        (unsigned)((MTU+MYNEWT_VAL(BLE_L2CAP_COC_MPS)-1)/MYNEWT_VAL(BLE_L2CAP_COC_MPS)),
        (unsigned)MYNEWT_VAL(BLE_L2CAP_COC_SDU_BUFF_COUNT),
        (unsigned)INTERVAL_UNITS*1250,(unsigned)MAX_CE_UNITS*625);
    return ESP_OK;
}
void wble_mesh_scan_interest(bool available)
{
    if(atomic_load(&quiescing))return;
    if(atomic_exchange(&scan_interest,available)==available)return;
    /* Block only NEW submissions while a resumed scan awaits its successful
     * start/listen window. The immutable queued DIAL is never rechecked. */
    atomic_store(&scan_listen_pending,available);
    if(atomic_load(&ready) && wble_gap_submit(&control,WBLE_GAP_SCAN,NULL))
        ble_npl_eventq_put(nimble_port_get_dflt_eventq(),&control_event);
}
esp_err_t wble_mesh_scan(wble_mesh_report callback,void *context)
{
    if(!atomic_load(&ready) || atomic_load(&quiescing) || !callback)return ESP_ERR_INVALID_STATE;
    if(!trylock())return ESP_ERR_INVALID_STATE;
    report=callback;report_context=context;
    bool wanted=atomic_load(&scan_interest) && !scan_paused;
    bool needed=(scan_owned!=wanted || (wanted && atomic_load(&scan_listen_pending))) &&
        wble_gap_retry_due(&scan_retry,esp_timer_get_time());
    unlock();
    if(needed && wble_gap_submit(&control,WBLE_GAP_SCAN,NULL))
        ble_npl_eventq_put(nimble_port_get_dflt_eventq(),&control_event);
    return ESP_OK;
}
int wble_mesh_poll_error(unsigned *operation)
{
    /* IDF's NPL queue put is zero-time and can refuse a full host queue.
     * Retain the mailbox intent and retry publication from the outer loop. */
    if(atomic_load(&starting) && !atomic_load(&control_stop_ack) && atomic_load(&control.pending))
        ble_npl_eventq_put(nimble_port_get_dflt_eventq(),&control_event);
    return wble_gap_error(&control,operation);
}
int64_t wble_mesh_retry_deadline(void)
{
    int64_t now=esp_timer_get_time();
    int64_t init=wble_gap_retry_deadline(&init_retry,now),scan=wble_gap_retry_deadline(&scan_retry,now);
    return init<scan ? init:scan;
}
bool wble_mesh_stop(void)
{
    /* Explicit OFF cancels pacing; internal failed-init cleanup preserves it. */
    atomic_store(&quiescing,true);
    wble_gap_retry_clear(&init_retry);wble_gap_retry_clear(&scan_retry);
    bool done=stop_resources();
    /* Host work was allowed to finish while OFF drained. Clear once more
     * after its acknowledgement, so a late error cannot pace the next ON. */
    if(done){wble_gap_retry_clear(&init_retry);wble_gap_retry_clear(&scan_retry);}
    return done;
}
static bool stop_resources(void)
{
    if(!atomic_load(&starting))return true;
    atomic_store(&quiescing,true);wble_report_close(&report_lifetime);
    if(!atomic_load_explicit(&control_stop_ack,memory_order_acquire)){
        if(wble_gap_submit(&control,WBLE_GAP_STOP,NULL))
            ble_npl_eventq_put(nimble_port_get_dflt_eventq(),&control_event);
        return false;
    }
    /* The host acknowledged no channel/dial/callback references or queued
     * mesh events. Timer publishers have a separate explicit drain gate. */
    if(!wble_report_drained(&timer_lifetime) || !wble_report_drained(&report_lifetime))return false;
    atomic_store(&ready,false);
    if(retry_timer){esp_timer_stop(retry_timer);esp_timer_delete(retry_timer);retry_timer=NULL;}
    ble_npl_event_deinit(&retry_event);ble_npl_event_deinit(&existing_event);
    ble_npl_event_deinit(&dial_timeout_event);ble_npl_event_deinit(&control_event);
    wendy_net_free(pool_memory);pool_memory=NULL;timer_running=false;
    scan_paused=dialing=dial_gap_pending=dial_timeout_posted=false;
    vSemaphoreDelete(mutex);mutex=NULL;
    wendy_net_memory_release(&sdk_memory);atomic_store(&starting,false);
    return true;
}
esp_err_t wble_mesh_dial(const uint8_t address[6],uint8_t type,uint16_t psm)
{
    if(!atomic_load(&ready) || atomic_load(&quiescing) || !address || type>3 || psm<128 || psm>255)
        return ESP_ERR_INVALID_ARG;
    if(!trylock())return ESP_ERR_INVALID_STATE;
    if(dialing || pending || count()>=CHANNELS || atomic_load(&scan_listen_pending) ||
       (scan_owned && esp_timer_get_time()<scan_dial_after)){
        unlock();return ESP_ERR_INVALID_STATE;
    }
    struct wble_gap_dial command={.type=type,.psm=psm,.epoch=++dial_epoch};
    memcpy(command.address,address,6);
    dialing=true;dial_gap_pending=false;scan_paused=true;dial_psm=psm;
    dial_until=esp_timer_get_time()+INT64_C(20000000);
    bool submitted=wble_gap_submit(&control,WBLE_GAP_DIAL,&command);
    if(!submitted){dialing=false;scan_paused=false;}
    unlock();
    if(!submitted)return ESP_ERR_INVALID_STATE;
    ble_npl_eventq_put(nimble_port_get_dflt_eventq(),&control_event);
    return ESP_OK;
}
static int dial_host(const struct wble_gap_dial *command)
{
    lock();bool current=dialing && command->epoch==dial_epoch && !atomic_load(&quiescing);unlock();
    if(!current)return BLE_HS_EALREADY;
    if(ble_gap_disc_active()){
        lock();bool ours=scan_owned;unlock();
        if(!ours){lock();dialing=false;scan_paused=false;unlock();return BLE_HS_EBUSY;}
    }
    if (ble_gap_disc_active()){int rc=ble_gap_disc_cancel();if(rc && rc!=BLE_HS_EALREADY){
        lock();dialing=false;scan_paused=false;unlock();return rc;}}
    ble_addr_t peer = {.type = command->type};
    memcpy(peer.val, command->address, 6);
    struct ble_gap_conn_desc existing;
    if (!ble_gap_conn_find_by_addr(&peer, &existing))
    {
        lock();
        existing_handle = existing.conn_handle;
        existing_epoch = command->epoch;
        unlock();
        ble_npl_eventq_put(nimble_port_get_dflt_eventq(), &existing_event);
        return ESP_OK;
    }
    struct ble_gap_conn_params params = {.scan_itvl = 160,
                                         .scan_window = 80,
                                         .itvl_min = INTERVAL_UNITS,
                                         .itvl_max = INTERVAL_UNITS,
                                         .latency = 0,
                                         .supervision_timeout = 400,
                                         .min_ce_len = 0,
                                         .max_ce_len = MAX_CE_UNITS};
    lock();
    dial_gap_pending = true;
    unlock();
    int rc = ble_gap_connect(own_type, &peer, 15000, &params, dial_gap_event,
                             (void *)(uintptr_t)command->epoch);
    if (rc)
    {
        lock();
        dialing = false;
        dial_gap_pending = false;
        scan_paused = false;
        unlock();
        start_scan();
        return rc;
    }
    return ESP_OK;
}
/* The host owns all GAP calls, including ordinary stop/cancellation. Keep the
 * callback contexts and pipe resources until this queue has drained them. */
static int stop_host(void)
{
    lock();report=NULL;report_context=NULL;
    atomic_store(&router_accepting,false);
    for(unsigned i=0;i<CHANNELS;i++){
        struct wble_mesh_pipe *p=pipes[i];
        if(p && atomic_exchange(&p->release_requested,false))p->owned=false;
        if(p && !p->owned)close_pipe(p);
    }
    bool cancel_scan=!stop_commands_done && scan_owned;
    bool cancel_dial=!stop_commands_done && dial_gap_pending;
    if(dialing && !dial_gap_pending){
        ble_npl_eventq_remove(nimble_port_get_dflt_eventq(),&existing_event);
        dialing=false;
    }
    unlock();
    int result=0;
    if(cancel_scan && ble_gap_disc_active()){
        int rc=ble_gap_disc_cancel();if(rc && rc!=BLE_HS_EALREADY)result=rc;
    }
    if(cancel_dial){
        int rc=ble_gap_conn_cancel();
        if(rc==BLE_HS_EALREADY && !ble_gap_conn_active()){
            lock();dialing=false;dial_gap_pending=false;unlock();
        }else if(rc && rc!=BLE_HS_EALREADY)result=rc;
    }
    if(result)return result; /* Next outer STOP poll retries this exact intent. */
    stop_commands_done=true;
    for(unsigned i=0;i<MYNEWT_VAL(BLE_MAX_CONNECTIONS);i++)
        if(stopping_acls[i].used && !stopping_acls[i].sent)terminate_unclaimed(stopping_acls[i].handle);
    lock();scan_owned=false;
    bool busy=count()!=0 || dialing || dial_gap_pending ||
        wble_gap_retiring_busy(stopping_acls,MYNEWT_VAL(BLE_MAX_CONNECTIONS)) ||
        !wble_report_drained(&report_lifetime) || (pool_memory && pool.mp_num_free!=SDUS);
    unlock();
    if(busy)return 0;
    wble_report_close(&timer_lifetime);
    if(retry_timer)esp_timer_stop(retry_timer);
    if(!wble_report_drained(&timer_lifetime))return 0;
    struct ble_npl_eventq *queue=nimble_port_get_dflt_eventq();
    ble_npl_eventq_remove(queue,&retry_event);ble_npl_eventq_remove(queue,&existing_event);
    ble_npl_eventq_remove(queue,&dial_timeout_event);ble_npl_eventq_remove(queue,&control_event);
    atomic_store(&control.pending,0);
    atomic_store(&ready,false);
    /* Last publication: actor can now dispose SDK event/semaphore resources.
     * This callback has no subsequent access to their allocated contents. */
    atomic_store_explicit(&control_stop_ack,true,memory_order_release);
    return 0;
}
static void control_run(struct ble_npl_event *event)
{
    (void)event;struct wble_gap_command command;
    if(!wble_gap_take(&control,&command))return;
    int result=command.action==WBLE_GAP_INIT ? initialize_host():
        command.action==WBLE_GAP_SCAN ? start_scan():
        command.action==WBLE_GAP_DIAL ? dial_host(&command.dial):stop_host();
    wble_gap_complete(&control,command.action,result);
    if(command.action==WBLE_GAP_INIT){
        if(result && !atomic_load(&quiescing))wble_gap_retry_failed(&init_retry,esp_timer_get_time());
        else if(!result)wble_gap_retry_clear(&init_retry);
        atomic_store(&control_init_done,true);
    }
    if(!atomic_load(&control_stop_ack) && atomic_load(&control.pending))
        ble_npl_eventq_put(nimble_port_get_dflt_eventq(),&control_event);
    wake_actor();
}
struct wble_mesh_pipe *wble_mesh_take(struct wble_mesh_peer *peer)
{
    if (!atomic_load(&ready) || !peer)
        return NULL;
    if(!trylock())return NULL;
    if (dialing && esp_timer_get_time() >= dial_until && !dial_timeout_posted) {
        dial_timeout_posted = true;
        ble_npl_eventq_put(nimble_port_get_dflt_eventq(), &dial_timeout_event);
    }
    struct wble_mesh_pipe *found = NULL;
    for (unsigned i = 0; i < CHANNELS; i++)
        if (pipes[i] && pipes[i]->connected && !pipes[i]->owned &&
            !pipes[i]->closing)
        {
            found = pipes[i];
            found->owned = true;
            *peer = found->peer;
            break;
        }
    unlock();
    return found;
}
static ssize_t stream_read(void *context, void *data, size_t size)
{
    struct wble_mesh_pipe *p = context;
    if (!size)
        return 0;
    if(!trylock())return -2;
    size_t n = size < p->ring_size ? size : p->ring_size;
    size_t first = sizeof p->ring - p->ring_head;
    if (first > n)
        first = n;
    memcpy(data, p->ring + p->ring_head, first);
    if (n > first)
        memcpy((uint8_t *)data + first, p->ring, n - first);
    p->ring_head = (p->ring_head + n) % sizeof p->ring;
    p->ring_size -= n;
    bool closed = !p->connected || p->closing;
    if (!closed && wble_rx_rearm_budget(RX_SLOTS,p->rx_owed,sizeof p->ring-p->ring_size,MTU))
        post(p);
    unlock();
    return n ? (ssize_t)n : closed ? 0 : -2;
}
static ssize_t stream_write(void *context, const void *data, size_t size)
{
    struct wble_mesh_pipe *p = context;
    if (!size)
        return 0;
    if(!trylock())return -3;
    if (!p->connected || p->closing)
    {
        unlock();
        return -1;
    }
    if (p->tx_pending || p->stalled)
    {
        unlock();
        return -3;
    }
    size_t n = size < TX_MAX ? size : TX_MAX;
    if (n > p->tx_mtu)
        n = p->tx_mtu;
    if (!n)
    {
        unlock();
        return -1;
    }
    memcpy(p->tx, data, n);
    p->tx_size = n;
    p->tx_pending = true;
    post(p);
    unlock();
    return (ssize_t)n;
}
static int stream_wait(void *context, bool writing, int64_t deadline)
{
    struct wble_mesh_pipe *p = context;
    lock();
    bool available =
        !p->connected || p->closing ||
        (writing ? !p->tx_pending && !p->stalled : p->ring_size > 0);
    unlock();
    int64_t left = deadline - esp_timer_get_time();
    if (available || left <= 0)
        return 0;
    TickType_t ticks = pdMS_TO_TICKS((left + 999) / 1000);
    if (!ticks)
        ticks = 1;
    xSemaphoreTake(p->wake, ticks);
    return 0; /* Hint; caller rechecks state/time. */
}
struct wendy_pki_stream wble_mesh_stream(struct wble_mesh_pipe *p)
{
    return (struct wendy_pki_stream){.context = p,
                                     .read = stream_read,
                                     .write = stream_write,
                                     .wait = stream_wait};
}
bool wble_mesh_output_drained(struct wble_mesh_pipe *p)
{
    if(!p || !atomic_load(&ready) || !mutex || !trylock())return false;
    bool drained=p->owned && p->connected && !p->closing && !p->tx_pending && !p->stalled;
    unlock();return drained;
}
void wble_mesh_release(struct wble_mesh_pipe *p)
{
    if(!p || !atomic_load(&ready))return;
    /* owned pins the pipe until its host timer consumes this final store.
     * The caller relinquishes its pointer and never waits for the host. */
    atomic_store_explicit(&p->release_requested,true,memory_order_release);
}
size_t wble_mesh_memory(void)
{
    if (!atomic_load(&ready))
        return 0;
    static atomic_size_t previous;
    if(!trylock())return atomic_load(&previous);
    size_t bytes = sdk_memory.bytes;
    for(unsigned i=0;i<CHANNELS;i++)if(pipes[i])
        bytes += wendy_net_memory_charge(sizeof(struct wble_mesh_pipe)) + pipes[i]->sdk_memory.bytes;
    if (pool_memory)
        bytes += wendy_net_memory_charge(OS_MEMPOOL_SIZE(SDUS, BLOCK) * sizeof *pool_memory);
    atomic_store(&previous,bytes);unlock();
    return bytes;
}

bool wble_mesh_uses_connection(uint16_t handle)
{
    /* The report publication loan also protects mutex/pipes against OFF's
     * final resource deletion. Never turn unknown state into an idle claim. */
    if(!wble_report_acquire(&report_lifetime))return true;
    bool used=true;
    if(trylock()){
        used=false;
        for(unsigned i=0;i<CHANNELS;i++)if(pipes[i] && pipes[i]->handle==handle){used=true;break;}
        unlock();
    }
    wble_report_release(&report_lifetime);
    return used;
}
