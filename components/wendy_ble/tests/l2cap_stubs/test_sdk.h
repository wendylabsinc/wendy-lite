#pragma once
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef int esp_err_t;
#define ESP_OK 0
#define ESP_FAIL -1
#define ESP_ERR_NO_MEM -2
#define ESP_ERR_INVALID_STATE -3
#define pdTRUE 1
#define ESP_LOGI(tag, ...) do { if (0) printf(__VA_ARGS__); } while (0)
#define ESP_LOGE(tag, ...) ESP_LOGI(tag, __VA_ARGS__)
#define ESP_LOGD(tag, ...) ESP_LOGI(tag, __VA_ARGS__)
#define ESP_LOGW(tag, ...) ESP_LOGI(tag, __VA_ARGS__)
static inline const char *esp_err_to_name(int e) { return "stub"; }
typedef void *esp_timer_handle_t;
typedef struct { void (*callback)(void *); const char *name; } esp_timer_create_args_t;
static inline int esp_timer_create(const esp_timer_create_args_t *a, esp_timer_handle_t *t) { return 0; }
static inline int esp_timer_start_once(esp_timer_handle_t t, uint64_t us) { return 0; }
static inline int eventfd(unsigned value, int flags) { return -1; }

typedef unsigned TickType_t;
typedef int *SemaphoreHandle_t;
#define portMAX_DELAY UINT32_MAX
struct ble_npl_event { void (*fn)(struct ble_npl_event *); };
extern struct ble_npl_event *test_queued;
extern bool test_on_host;
extern void (*test_before_host_event)(void);
static inline void ble_npl_event_init(struct ble_npl_event *e, void (*fn)(struct ble_npl_event *), void *arg) { e->fn = fn; }
static inline void *nimble_port_get_dflt_eventq(void) { return NULL; }
static inline void ble_npl_eventq_put(void *q, struct ble_npl_event *e) { assert(!test_queued); test_queued = e; }
static inline SemaphoreHandle_t xSemaphoreCreateBinary(void) { return calloc(1, sizeof(int)); }
static inline SemaphoreHandle_t xSemaphoreCreateMutex(void) { int *s = xSemaphoreCreateBinary(); *s = 1; return s; }
static inline int xSemaphoreGive(int *s) { *s = 1; return 1; }
static inline int xSemaphoreTake(int *s, unsigned timeout) {
    if (!*s && test_queued) {
        struct ble_npl_event *e = test_queued; test_queued = NULL;
        test_on_host = true;
        if (test_before_host_event) test_before_host_event();
        e->fn(e);
        test_on_host = false;
    }
    if (!*s) return 0;
    *s = 0; return 1;
}

#define BLE_HS_CONN_HANDLE_NONE UINT16_MAX
#define BLE_HS_ENOMEM 1
#define BLE_HS_ENOTCONN 2
#define BLE_HS_ESTALLED 3
#define BLE_HS_EBUSY 4
#define BLE_HS_EBADDATA 5
#define BLE_ERR_REM_USER_CONN_TERM 19
#define BLE_L2CAP_EVENT_COC_ACCEPT 1
#define BLE_L2CAP_EVENT_COC_CONNECTED 2
#define BLE_L2CAP_EVENT_COC_DISCONNECTED 3
#define BLE_L2CAP_EVENT_COC_DATA_RECEIVED 4
#define BLE_L2CAP_EVENT_COC_TX_UNSTALLED 5
typedef unsigned os_membuf_t;
#define OS_MEMPOOL_SIZE(n, size) ((n) * (size))
struct os_mempool { int unused; };
struct os_mbuf_pool { int unused; };
struct os_mbuf { size_t len; uint8_t data[512]; };
static inline int os_msys_num_free(void) { return 24; }
static inline int os_msys_count(void) { return 24; }
#define OS_MBUF_PKTLEN(m) ((m)->len)
static inline int os_mempool_init(struct os_mempool *p, int n, int size, void *mem, const char *name) { return 0; }
static inline int os_mbuf_pool_init(struct os_mbuf_pool *p, struct os_mempool *m, int size, int n) { return 0; }
static inline struct os_mbuf *os_mbuf_get_pkthdr(struct os_mbuf_pool *p, int extra) { return calloc(1, sizeof(struct os_mbuf)); }
static inline void os_mbuf_free_chain(struct os_mbuf *m) { free(m); }
static inline int os_mbuf_copydata(struct os_mbuf *m, int offset, int size, void *out) { memcpy(out, m->data + offset, size); return 0; }
static inline int os_mbuf_append(struct os_mbuf *m, const void *data, int n) { memcpy(m->data + m->len, data, n); m->len += n; return 0; }
struct ble_l2cap_chan { int id; };
static inline uint16_t ble_l2cap_get_conn_handle(struct ble_l2cap_chan *c) { return c->id; }
struct ble_l2cap_chan_info { uint16_t peer_coc_mtu, peer_l2cap_mtu; };
struct ble_l2cap_event {
    int type;
    struct { struct ble_l2cap_chan *chan; uint16_t conn_handle; } accept, disconnect;
    struct { struct ble_l2cap_chan *chan; uint16_t conn_handle; int status; } connect;
    struct { struct ble_l2cap_chan *chan; struct os_mbuf *sdu_rx; } receive;
};
extern unsigned test_gap_closes, test_channel_closes;
extern uint16_t test_closed_peer;
static inline int ble_gap_terminate(uint16_t peer, uint8_t reason) {
    assert(test_on_host && reason == BLE_ERR_REM_USER_CONN_TERM);
    ++test_gap_closes; test_closed_peer = peer; return 0;
}
static inline int ble_l2cap_disconnect(struct ble_l2cap_chan *c) { assert(test_on_host); ++test_channel_closes; return 0; }
static inline int ble_l2cap_get_chan_info(struct ble_l2cap_chan *c, struct ble_l2cap_chan_info *i) { i->peer_coc_mtu = 512; i->peer_l2cap_mtu = 247; return 0; }
static inline int ble_l2cap_recv_ready(struct ble_l2cap_chan *c, struct os_mbuf *sdu) { free(sdu); return 0; }
static inline int ble_l2cap_send(struct ble_l2cap_chan *c, struct os_mbuf *sdu) { free(sdu); return 0; }
static inline int ble_l2cap_create_server(uint16_t psm, int mtu, int (*cb)(struct ble_l2cap_event *, void *), void *arg) { return 0; }
