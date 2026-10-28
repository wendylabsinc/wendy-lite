/* Normal, finite ordinary-pool pressure. Actual patched SDK functions are
 * included below; only platform lock, mbuf pool and transport edges are stubbed. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>
#include <limits.h>

#ifndef TEST_RX_SLOTS
#define TEST_RX_SLOTS 2
#endif
#define BLE_L2CAP_SDU_BUFF_CNT TEST_RX_SLOTS
#define BLE_L2CAP_COC_RX_CREDITS_INITIAL 0x02
#define BLE_L2CAP_COC_RX_CREDITS_PARTIAL 0x04
#define BLE_L2CAP_COC_RX_CREDITS_PENDING 0x06
#define BLE_L2CAP_CHAN_F_DISCONNECTING 0x02
#define BLE_L2CAP_CID_SIG 5
#define BLE_L2CAP_SIG_OP_FLOW_CTRL_CREDIT 0x16
#define BLE_L2CAP_SDU_SIZE 2
#define BLE_L2CAP_COC_MAX_NUM 4
#define BLE_L2CAP_ENHANCED_COC 0
#define MYNEWT_VAL(x) (x)
#define BLE_HS_FOREVER INT32_MAX
#define BLE_HS_EINVAL 3
#define BLE_HS_ENOMEM 6
#define BLE_HS_ENOENT 7
#define BLE_HS_EBUSY 15
#define BLE_HS_EAGAIN 1
#define BLE_HS_EBADDATA 10
#define BLE_HS_ETIMEOUT 13
#define BLE_L2CAP_SIG_PROC_OP_UPDATE 1
#define BLE_L2CAP_SIG_PROC_OP_CONNECT 2
#define BLE_L2CAP_SIG_PROC_OP_DISCONNECT 3
#define BLE_HS_LOG(...) ((void)0)
#define BLE_HS_DBG_ASSERT(x) assert(x)
#define STATS_INC(...) ((void)0)
#define max(a,b) ((a) > (b) ? (a) : (b))
#define OS_MBUF_PKTLEN(om) ((om)->len)
#define OS_MBUF_PKTHDR(om) (om)
#define htole16(x) (x)

struct os_mbuf {
    STAILQ_ENTRY(os_mbuf) omp_next;
    unsigned len;
    uint8_t *om_data;
    uint8_t bytes[640];
    bool pooled, used;
};
#include "nimble_credit_endpoint.inc"
struct ble_l2cap_chan {
    SLIST_ENTRY(ble_l2cap_chan) next;
    uint16_t conn_handle, scid, dcid, psm, initial_credits;
    uint8_t flags;
    bool disable_auto_credit_update;
    struct ble_l2cap_coc_endpoint coc_rx;
};
SLIST_HEAD(channel_list, ble_l2cap_chan);
struct ble_hs_conn {
    SLIST_ENTRY(ble_hs_conn) bhc_next;
    uint16_t handle;
    struct channel_list bhc_channels;
    STAILQ_HEAD(, os_mbuf) bhc_tx_q;
};
SLIST_HEAD(connection_list, ble_hs_conn);
static struct connection_list connections;
struct ble_l2cap_sig_hdr {
    uint8_t op, identifier;
    uint16_t length;
    uint8_t data[];
};
struct ble_l2cap_sig_le_credits { uint16_t scid, credits; };
struct ble_l2cap_sig_proc {
    STAILQ_ENTRY(ble_l2cap_sig_proc) next;
    int op;
};
STAILQ_HEAD(ble_l2cap_sig_proc_list, ble_l2cap_sig_proc);
static int locked, reschedules, grant_pdus, received_sdus, received_bytes;
static int pool_in_use, pool_peak, pool_allocations, credit_sum[128];
static bool controller_backed_up;
static int32_t procedure_deadline = BLE_HS_FOREVER;
static struct os_mbuf ordinary_pool[2];
static unsigned pool_capacity = 2;
static uint8_t completed[1024];

static void ble_hs_lock(void) { assert(!locked); locked = 1; }
static void ble_hs_unlock(void) { assert(locked); locked = 0; }
static bool ble_hs_locked_by_cur_task(void) { return locked; }
static void ble_hs_timer_resched(void) { reschedules++; }
static int32_t ble_npl_time_ms_to_ticks32(unsigned ms) { return (int32_t)ms; }
static struct ble_hs_conn *ble_hs_conn_first(void) {
    assert(locked); return SLIST_FIRST(&connections);
}
static struct ble_hs_conn *ble_hs_conn_find_assert(uint16_t handle) {
    struct ble_hs_conn *conn;
    assert(locked);
    SLIST_FOREACH(conn, &connections, bhc_next) if (conn->handle == handle) return conn;
    assert(!"live connection required"); return NULL;
}
static struct ble_l2cap_chan *ble_hs_conn_chan_find_by_scid(struct ble_hs_conn *conn, uint16_t cid) {
    struct ble_l2cap_chan *chan;
    assert(locked);
    SLIST_FOREACH(chan, &conn->bhc_channels, next) if (chan->scid == cid) return chan;
    return NULL;
}
static int ble_hs_misc_conn_chan_find_reqd(uint16_t handle, uint16_t cid,
                                          struct ble_hs_conn **conn, struct ble_l2cap_chan **chan) {
    *conn = ble_hs_conn_find_assert(handle);
    *chan = ble_hs_conn_chan_find_by_scid(*conn, cid);
    return *chan ? 0 : BLE_HS_ENOENT;
}
static struct os_mbuf *ble_hs_mbuf_l2cap_pkt(void) {
    for (unsigned i = 0; i < pool_capacity; ++i) if (!ordinary_pool[i].used) {
        struct os_mbuf *om = &ordinary_pool[i];
        memset(om, 0, sizeof(*om)); om->used = om->pooled = true; om->om_data = om->bytes;
        pool_allocations++; pool_in_use++;
        if (pool_in_use > pool_peak) pool_peak = pool_in_use;
        return om;
    }
    return NULL;
}
static void os_mbuf_free_chain(struct os_mbuf *om) {
    if (om && om->pooled) { assert(om->used); om->used = false; assert(pool_in_use > 0); pool_in_use--; }
}
static void *os_mbuf_extend(struct os_mbuf *om, unsigned size) {
    assert(om->len + size <= sizeof(om->bytes));
    void *result = om->om_data + om->len; om->len += size; return result;
}
static struct os_mbuf *ble_l2cap_prepend_hdr(struct os_mbuf *om, uint16_t cid, unsigned len) {
    assert(cid == BLE_L2CAP_CID_SIG && len == 8); return om;
}
static void send_credit(struct os_mbuf *om) {
    struct ble_l2cap_sig_hdr *hdr = (void *)om->om_data;
    struct ble_l2cap_sig_le_credits *cmd = (void *)hdr->data;
    assert(hdr->op == BLE_L2CAP_SIG_OP_FLOW_CTRL_CREDIT && hdr->length == sizeof(*cmd));
    assert(cmd->scid < 128 && cmd->credits > 0);
    grant_pdus++; credit_sum[cmd->scid] += cmd->credits;
    os_mbuf_free_chain(om);
}
static int ble_hs_hci_acl_tx(struct ble_hs_conn *conn, struct os_mbuf **om) {
    (void)conn; assert(locked);
    if (controller_backed_up) return BLE_HS_EAGAIN;
    send_credit(*om); *om = NULL; return 0;
}
static uint8_t ble_l2cap_sig_next_id(void) { static uint8_t id; assert(locked); return ++id; }
static int ble_hs_mbuf_pullup_base(struct os_mbuf **om, unsigned size) {
    assert((*om)->len >= size); return 0;
}
static uint16_t get_le16(const uint8_t *data) { return (uint16_t)(data[0] | data[1] << 8); }
static void os_mbuf_adj(struct os_mbuf *om, unsigned size) { assert(size <= om->len); om->om_data += size; om->len -= size; }
static int os_mbuf_appendfrom(struct os_mbuf *out, struct os_mbuf *in, unsigned at, unsigned len) {
    assert(at + len <= in->len && out->len + len <= sizeof(out->bytes));
    memcpy(out->om_data + out->len, in->om_data + at, len); out->len += len; return 0;
}
static void ble_l2cap_disconnect(struct ble_l2cap_chan *chan) { (void)chan; assert(!"unexpected disconnect"); }
static void ble_l2cap_event_coc_received_data(struct ble_l2cap_chan *chan, struct os_mbuf *om) {
    (void)chan; assert(!locked); assert(om->len <= sizeof(completed));
    memcpy(completed, om->om_data, om->len); received_sdus++; received_bytes += om->len;
}
static int32_t ble_l2cap_sig_extract_expired(struct ble_l2cap_sig_proc_list *list) {
    STAILQ_INIT(list); return procedure_deadline;
}
static void ble_l2cap_sig_update_call_cb(struct ble_l2cap_sig_proc *p, int rc) { (void)p; (void)rc; }
static void ble_l2cap_sig_coc_connect_cb(struct ble_l2cap_sig_proc *p, int rc) { (void)p; (void)rc; }
static void ble_l2cap_sig_coc_disconnect_cb(struct ble_l2cap_sig_proc *p, int rc) { (void)p; (void)rc; }
static void ble_l2cap_sig_proc_free(struct ble_l2cap_sig_proc *p) { (void)p; }
#include "nimble_credit_production.inc"

static void init_mbuf(struct os_mbuf *om) { memset(om, 0, sizeof(*om)); om->om_data = om->bytes; }
static void connect_channel(struct ble_hs_conn *conn, struct ble_l2cap_chan *sig,
                            struct ble_l2cap_chan *chan, uint16_t handle, uint16_t cid) {
    memset(conn, 0, sizeof(*conn)); memset(sig, 0, sizeof(*sig)); memset(chan, 0, sizeof(*chan));
    conn->handle = handle; SLIST_INIT(&conn->bhc_channels); STAILQ_INIT(&conn->bhc_tx_q);
    SLIST_INSERT_HEAD(&connections, conn, bhc_next);
    sig->scid = sig->dcid = BLE_L2CAP_CID_SIG;
    SLIST_INSERT_HEAD(&conn->bhc_channels, sig, next);
    chan->conn_handle = handle; chan->scid = cid; chan->psm = 0x81;
    chan->initial_credits = 1; chan->coc_rx.mtu = 64;
    SLIST_INSERT_HEAD(&conn->bhc_channels, chan, next);
}
static void incoming(struct ble_l2cap_chan *chan, const uint8_t *bytes, unsigned count) {
    struct os_mbuf packet; init_mbuf(&packet);
    memcpy(packet.bytes, bytes, count); packet.len = count;
    struct os_mbuf *p = &packet;
    assert(ble_l2cap_coc_rx_fn(chan, &p) == 0);
}
#if TEST_RX_SLOTS > 1
static void deferred_backed_window(void) {
    struct ble_hs_conn conn;
    struct ble_l2cap_chan sig, chan;
    struct os_mbuf old_rx, parked_rx;
    const uint8_t short_sdu[] = {3, 0, 'x', 'y', 'z'};
    int before_pdus = grant_pdus, before_sdus = received_sdus;
    connect_channel(&conn, &sig, &chan, 3, 66);
    init_mbuf(&old_rx); init_mbuf(&parked_rx);
    chan.initial_credits = 2;
    chan.coc_rx.credits = 1; /* One earlier credit is already at the peer. */
    chan.coc_rx.sdus[0] = &old_rx;
    chan.coc_rx.next_sdu_alloc_idx = 1;
    struct os_mbuf *busy0 = ble_hs_mbuf_l2cap_pkt();
    struct os_mbuf *busy1 = ble_hs_mbuf_l2cap_pkt();
    assert(busy0 && busy1);
    assert(ble_l2cap_coc_recv_ready(&chan, &parked_rx) == 0);
    assert(chan.coc_rx.sdus[1] == &parked_rx && chan.coc_rx.credits == 1);
    assert(chan.coc_rx.flags & BLE_L2CAP_COC_RX_CREDITS_INITIAL);
    incoming(&chan, short_sdu, sizeof(short_sdu));
    assert(received_sdus == before_sdus + 1 && chan.coc_rx.current_sdu_idx == 1);
    assert(!chan.coc_rx.sdus[0] && chan.coc_rx.credits == 0);
    os_mbuf_free_chain(busy0); os_mbuf_free_chain(busy1);
    assert(ble_l2cap_sig_timer() == BLE_HS_FOREVER);
    /* Only one buffer remains now. Recomputing the armed ring prevents the
     * old target of two from granting an unbacked short-SDU receive. */
    assert(grant_pdus == before_pdus + 1 && credit_sum[66] == 1);
    assert(chan.coc_rx.credits == 1 && !chan.coc_rx.flags);
    incoming(&chan, short_sdu, sizeof(short_sdu));
    assert(received_sdus == before_sdus + 2 && chan.coc_rx.credits == 0);
    assert(ble_l2cap_sig_timer() == BLE_HS_FOREVER && grant_pdus == before_pdus + 1);
    assert(!chan.coc_rx.sdus[1] && pool_in_use == 0);
    SLIST_REMOVE(&connections, &conn, ble_hs_conn, bhc_next);
}
#endif
int main(void) {
    struct ble_hs_conn conn, other;
    struct ble_l2cap_chan sig, chan, other_sig, other_chan;
    struct os_mbuf rx, other_rx, next_rx;
    SLIST_INIT(&connections);
    connect_channel(&conn, &sig, &chan, 1, 64);
    connect_channel(&other, &other_sig, &other_chan, 2, 65);
    init_mbuf(&rx); init_mbuf(&other_rx); init_mbuf(&next_rx);

    /* Two ordinary sends hold the entire shared pool. Posting an RX buffer
     * transfers it once but must not invent a remote credit. */
    struct os_mbuf *busy0 = ble_hs_mbuf_l2cap_pkt();
    struct os_mbuf *busy1 = ble_hs_mbuf_l2cap_pkt();
    assert(busy0 && busy1 && !ble_hs_mbuf_l2cap_pkt());
    assert(ble_l2cap_coc_recv_ready(&chan, &rx) == 0);
    assert(chan.coc_rx.sdus[0] == &rx && chan.coc_rx.next_sdu_alloc_idx == 1%BLE_L2CAP_SDU_BUFF_CNT);
    assert(chan.coc_rx.credits == 0 && grant_pdus == 0 && reschedules == 1);
    assert(ble_l2cap_coc_recv_ready(&other_chan, &other_rx) == 0);
    assert(reschedules == 2 && other_chan.coc_rx.credits == 0);
    for (unsigned i = 0; i < 5; ++i) assert(ble_l2cap_sig_timer() == 10);
    assert(reschedules == 2 && pool_in_use == 2); /* paced, no allocation growth */
    procedure_deadline = 3;
    assert(ble_l2cap_sig_timer() == 3); /* preserve an earlier existing deadline */
    procedure_deadline = BLE_HS_FOREVER;

    os_mbuf_free_chain(busy0); os_mbuf_free_chain(busy1);
    assert(ble_l2cap_sig_timer() == BLE_HS_FOREVER);
    assert(grant_pdus == 2 && credit_sum[64] == 1 && credit_sum[65] == 1);
    assert(chan.coc_rx.credits == 1 && other_chan.coc_rx.credits == 1);
    assert(pool_in_use == 0 && chan.coc_rx.next_sdu_alloc_idx == 1%BLE_L2CAP_SDU_BUFF_CNT);
    assert(ble_l2cap_sig_timer() == BLE_HS_FOREVER && grant_pdus == 2);

    /* A normal segmented six-byte SDU needs a continuation credit. Pool
     * pressure retains the partial bytes and retries without a second SDU. */
    busy0 = ble_hs_mbuf_l2cap_pkt(); busy1 = ble_hs_mbuf_l2cap_pkt();
    const uint8_t first[] = {6, 0, 'a', 'b', 'c'};
    incoming(&chan, first, sizeof(first));
    assert(chan.coc_rx.credits == 0 && rx.len == 3 && chan.coc_rx.sdus[0] == &rx);
    assert(reschedules == 3 && ble_l2cap_sig_timer() == 10 && received_sdus == 0);
    os_mbuf_free_chain(busy0); os_mbuf_free_chain(busy1);
    assert(ble_l2cap_sig_timer() == BLE_HS_FOREVER);
    assert(chan.coc_rx.credits == 1 && credit_sum[64] == 2 && pool_in_use == 0);
    const uint8_t rest[] = {'d', 'e', 'f'};
    incoming(&chan, rest, sizeof(rest));
    assert(received_sdus == 1 && received_bytes == 6 && !memcmp(completed, "abcdef", 6));
    assert(chan.coc_rx.sdus[0] == NULL && chan.coc_rx.credits == 0);
    assert(ble_l2cap_sig_timer() == BLE_HS_FOREVER && grant_pdus == 3);

    /* Existing HCI queue acceptance counts exactly once, although the
     * controller transmits later. No retry duplicates an accepted credit. */
    controller_backed_up = true;
    assert(ble_l2cap_coc_recv_ready(&chan, &next_rx) == 0);
    assert(chan.coc_rx.credits == 1 && pool_in_use == 1 && grant_pdus == 3);
    assert(ble_l2cap_sig_timer() == BLE_HS_FOREVER);
    struct os_mbuf *queued = STAILQ_FIRST(&conn.bhc_tx_q);
    assert(queued); STAILQ_REMOVE_HEAD(&conn.bhc_tx_q, omp_next);
    controller_backed_up = false; send_credit(queued);
    assert(pool_in_use == 0 && grant_pdus == 4 && credit_sum[64] == 3);

    /* Ordinary close retires pending intent without retaining a channel or
     * buffer reference in the timer. Auto-credit disable also cancels intent. */
    other_chan.coc_rx.credits = 0;
    other_chan.coc_rx.flags = BLE_L2CAP_COC_RX_CREDITS_INITIAL;
    other_chan.flags |= BLE_L2CAP_CHAN_F_DISCONNECTING;
    assert(ble_l2cap_sig_timer() == BLE_HS_FOREVER && !other_chan.coc_rx.flags);
    SLIST_REMOVE(&other.bhc_channels, &other_chan, ble_l2cap_chan, next);
    assert(ble_l2cap_sig_timer() == BLE_HS_FOREVER && grant_pdus == 4);
    chan.coc_rx.flags = BLE_L2CAP_COC_RX_CREDITS_INITIAL;
    chan.disable_auto_credit_update = true;
    assert(ble_l2cap_sig_timer() == BLE_HS_FOREVER && !chan.coc_rx.flags);
    assert(pool_in_use == 0 && pool_peak == 2 && !locked);
#if TEST_RX_SLOTS > 1
    deferred_backed_window();
#endif
    printf("credit fixture RXslots=%u PASS: %d exact grants, %d bytes, pool peak %d, allocations %d, no extra SDUs\n",TEST_RX_SLOTS,
           grant_pdus, received_bytes, pool_peak, pool_allocations);
    return 0;
}
