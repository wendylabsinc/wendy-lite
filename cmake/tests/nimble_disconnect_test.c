/* Valid local, peer and simultaneous close. Only lock, connection and wire
 * edges are mocked; the SDK owns procedure extraction and completion. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>
#ifndef STAILQ_REMOVE_AFTER
#define STAILQ_REMOVE_AFTER(head, elm, field) do { \
    if ((STAILQ_NEXT(elm, field) = STAILQ_NEXT(STAILQ_NEXT(elm, field), field)) == NULL) \
        (head)->stqh_last = &STAILQ_NEXT(elm, field); \
} while (0)
#endif
#define BLE_L2CAP_SIG_PROC_OP_DISCONNECT 3
#define BLE_L2CAP_SIG_OP_DISCONN_RSP 7
#define BLE_HS_EBADDATA 10
#define OS_MBUF_PKTLEN(om) ((om)->len)
#define BLE_HS_LOG(...) ((void)0)
#define htole16(x) (x)
#define le16toh(x) (x)
struct ble_l2cap_chan { uint16_t scid, dcid; bool live; };
struct ble_hs_conn { uint16_t handle; bool live; };
struct ble_l2cap_sig_proc {
    STAILQ_ENTRY(ble_l2cap_sig_proc) next;
    uint16_t conn_handle;
    uint8_t op, identifier;
    struct { struct ble_l2cap_chan *chan; } disconnect;
    bool freed;
};
STAILQ_HEAD(proc_list, ble_l2cap_sig_proc);
static struct proc_list ble_l2cap_sig_procs;
struct os_mbuf { unsigned len; void *om_data; };
struct ble_l2cap_sig_hdr { uint8_t identifier; };
struct ble_l2cap_sig_disc_req { uint16_t dcid, scid; };
struct ble_l2cap_sig_disc_rsp { uint16_t dcid, scid; };
static struct ble_hs_conn connection;
static struct ble_l2cap_chan channel;
static struct ble_l2cap_sig_disc_rsp reply;
static struct os_mbuf reply_mbuf;
static unsigned deletes, frees, responses;
static bool locked;
static void ble_hs_lock(void) { assert(!locked); locked = true; }
static void ble_hs_unlock(void) { assert(locked); locked = false; }
static int ble_hs_mbuf_pullup_base(struct os_mbuf **om, unsigned size) { assert((*om)->len == size); return 0; }
static void *ble_l2cap_sig_cmd_get(unsigned op, unsigned id, unsigned size, struct os_mbuf **out) {
    assert(op == BLE_L2CAP_SIG_OP_DISCONN_RSP && id == 42 && size == sizeof(reply));
    reply_mbuf = (struct os_mbuf){size, &reply}; *out = &reply_mbuf; return &reply;
}
static struct ble_hs_conn *ble_hs_conn_find(uint16_t handle) {
    assert(locked); return connection.live && handle == connection.handle ? &connection : NULL;
}
static struct ble_hs_conn *ble_hs_conn_find_assert(uint16_t handle) {
    struct ble_hs_conn *conn = ble_hs_conn_find(handle); assert(conn); return conn;
}
static bool ble_hs_conn_chan_exist(struct ble_hs_conn *conn, struct ble_l2cap_chan *chan) {
    assert(locked && conn == &connection); return chan == &channel && channel.live;
}
static struct ble_l2cap_chan *ble_hs_conn_chan_find_by_scid(struct ble_hs_conn *conn, uint16_t cid) {
    assert(locked && conn == &connection); return channel.live && channel.scid == cid ? &channel : NULL;
}
static void ble_hs_conn_delete_chan(struct ble_hs_conn *conn, struct ble_l2cap_chan *chan) {
    assert(ble_hs_conn_chan_exist(conn, chan)); channel.live = false; deletes++;
}
static void ble_l2cap_sig_proc_free(struct ble_l2cap_sig_proc *proc) {
    if (proc) { assert(!proc->freed); proc->freed = true; frees++; }
}
static void os_mbuf_free_chain(struct os_mbuf *om) { assert(om == &reply_mbuf); }
static int ble_l2cap_sig_tx(uint16_t handle, struct os_mbuf *om) {
    assert(!locked && handle == connection.handle && om == &reply_mbuf);
    assert(reply.dcid == 64 && reply.scid == 80); responses++; return 0;
}
static void ble_l2cap_sig_reject_invalid_cid_tx(uint16_t handle, uint8_t id, uint16_t scid, uint16_t dcid) {
    (void)handle; (void)id; (void)scid; (void)dcid; assert(!"unexpected invalid CID");
}
static struct ble_l2cap_sig_proc *ble_l2cap_sig_proc_extract(uint16_t handle, uint8_t op, uint8_t id) {
    struct ble_l2cap_sig_proc *proc, *prev = NULL;
    STAILQ_FOREACH(proc, &ble_l2cap_sig_procs, next) {
        if (proc->conn_handle == handle && proc->op == op && proc->identifier == id) {
            if (prev) STAILQ_REMOVE_AFTER(&ble_l2cap_sig_procs, prev, next);
            else STAILQ_REMOVE_HEAD(&ble_l2cap_sig_procs, next);
            return proc;
        }
        prev = proc;
    }
    return NULL;
}
static void ble_l2cap_sig_process_status(struct ble_l2cap_sig_proc *proc, int status) {
    (void)proc; (void)status; assert(!"unexpected retry of valid response");
}
#include "production.inc"
static void reset(void) {
    STAILQ_INIT(&ble_l2cap_sig_procs);
    connection = (struct ble_hs_conn){1, true}; channel = (struct ble_l2cap_chan){64, 80, true};
    deletes = frees = responses = 0; locked = false;
}
static struct ble_l2cap_sig_proc local_close(uint8_t id) {
    return (struct ble_l2cap_sig_proc){.conn_handle = 1,
        .op = BLE_L2CAP_SIG_PROC_OP_DISCONNECT, .identifier = id, .disconnect.chan = &channel};
}
static void peer_close(void) {
    struct ble_l2cap_sig_hdr hdr = {42};
    struct ble_l2cap_sig_disc_req req = {64, 80};
    struct os_mbuf packet = {sizeof(req), &req}, *om = &packet;
    assert(ble_l2cap_sig_disc_req_rx(1, &hdr, &om) == 0);
}
static void peer_response(uint8_t id) {
    struct ble_l2cap_sig_hdr hdr = {id};
    struct ble_l2cap_sig_disc_rsp rsp = {80, 64};
    struct os_mbuf packet = {sizeof(rsp), &rsp}, *om = &packet;
    assert(ble_l2cap_sig_disc_rsp_rx(1, &hdr, &om) == 0);
}
int main(void) {
    reset(); peer_close(); assert(deletes == 1 && responses == 1 && frees == 0);
    reset(); struct ble_l2cap_sig_proc local = local_close(12);
    STAILQ_INSERT_TAIL(&ble_l2cap_sig_procs, &local, next);
    peer_response(12); assert(deletes == 1 && frees == 1 && STAILQ_EMPTY(&ble_l2cap_sig_procs));

    /* Both peers close normally. Retire only this channel's pending request;
     * another connection's procedure stays live. The later response is inert. */
    reset(); local = local_close(12); struct ble_l2cap_sig_proc other = local_close(13);
    other.conn_handle = 2;
    STAILQ_INSERT_TAIL(&ble_l2cap_sig_procs, &other, next);
    STAILQ_INSERT_TAIL(&ble_l2cap_sig_procs, &local, next);
    peer_close(); peer_response(12);
    assert(deletes == 1 && responses == 1 && frees == 1 && local.freed && !other.freed);
    assert(STAILQ_FIRST(&ble_l2cap_sig_procs) == &other && STAILQ_NEXT(&other, next) == NULL);

    reset(); local = local_close(12); STAILQ_INSERT_TAIL(&ble_l2cap_sig_procs, &local, next);
    peer_close(); assert(STAILQ_EMPTY(&ble_l2cap_sig_procs) && frees == 1 && deletes == 1);

    /* Existing timeout / connection teardown completion owns only a live
     * membership. A retired channel or connection produces no second delete. */
    reset(); local = local_close(12);
    ble_l2cap_sig_coc_disconnect_cb(&local, 13); assert(deletes == 1);
    ble_l2cap_sig_coc_disconnect_cb(&local, 13); assert(deletes == 1);
    connection.live = false;
    ble_l2cap_sig_coc_disconnect_cb(&local, 13); assert(deletes == 1 && !locked);
    puts("actual SDK ordinary peer/local/crossed CoC close and teardown completion PASS");
    return 0;
}
