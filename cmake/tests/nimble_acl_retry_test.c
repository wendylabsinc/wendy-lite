/* Finite valid ACL traffic through actual SDK queue/fragmentation functions.
 * Platform allocation and controller acceptance/completion are bounded mocks. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>
#include <limits.h>
#ifndef TEST_ACL_MAX
#define TEST_ACL_MAX 251
#endif
#define BLE_ACL_MAX_PKT_SIZE TEST_ACL_MAX
#define SOC_ESP_NIMBLE_CONTROLLER 1
#define CONFIG_BT_CONTROLLER_ENABLED 1
#define BLE_MONITOR 1
#define BLE_HS_LOG_LVL 0
#define MYNEWT_VAL(x) x
#define BLE_HCI_PB_FIRST_NON_FLUSH 0
#define BLE_HCI_PB_MIDDLE 1
#define BLE_HS_CONN_F_TX_FRAG 1
#define BLE_HS_ENOMEM 6
#define BLE_HS_EAGAIN 1
#define BLE_HS_FOREVER INT32_MAX
typedef int32_t ble_npl_stime_t;
#define BLE_HS_DBG_ASSERT(x) assert(x)
#define BLE_HS_LOG(...) ((void)0)
#define os_mbuf_pkthdr os_mbuf
#define OS_MBUF_PKTLEN(m) ((m)->len)
#define OS_MBUF_PKTHDR(m) (m)
#define OS_MBUF_PKTHDR_TO_MBUF(m) (m)
struct os_mbuf {STAILQ_ENTRY(os_mbuf) omp_next;unsigned len;bool used,dedicated;uint8_t pb;uint8_t bytes[1024];};
struct ble_hs_conn {SLIST_ENTRY(ble_hs_conn) bhc_next;uint16_t bhc_handle;unsigned bhc_flags,bhc_outstanding_pkts;STAILQ_HEAD(,os_mbuf) bhc_tx_q;};
struct ble_l2cap_chan {uint16_t dcid;};
static struct os_mbuf shared[8],dedicated;
static struct ble_hs_conn connection;
static unsigned ble_hs_hci_avail_pkts,peak_shared,wire_size,wire_fragments,fail_after;
static uint8_t wire[2048],pbs[256];
static bool locked,transport_pressure,connection_live;
static int32_t clock_ticks,scheduled;
#if HAVE_RETRY_TIMER
static bool ble_hs_tx_retry_pending;
static int32_t ble_hs_tx_retry_due;
#endif
static void ble_hs_lock(void){assert(!locked);locked=true;}
static void ble_hs_unlock(void){assert(locked);locked=false;}
static bool ble_hs_locked_by_cur_task(void){return locked;}
static struct ble_hs_conn *ble_hs_conn_first(void){assert(locked);return connection_live ? &connection:NULL;}
static int32_t ble_npl_time_get(void){return clock_ticks;}
static int32_t ble_npl_time_ms_to_ticks32(unsigned ms){return (int32_t)ms;}
static void ble_hs_timer_sched(int32_t ticks){if(ticks<scheduled)scheduled=ticks;}
static struct os_mbuf *alloc_shared(void){
 unsigned used=0;for(unsigned i=0;i<8;i++)used+=shared[i].used;
 for(unsigned i=0;i<8;i++)if(!shared[i].used){struct os_mbuf *m=&shared[i];memset(m,0,sizeof *m);m->used=true;if(used+1>peak_shared)peak_shared=used+1;return m;}return NULL;
}
static void os_mbuf_free_chain(struct os_mbuf *m){if(m){assert(m->used);m->used=false;}}
static struct os_mbuf *ble_hs_hci_frag_alloc(uint16_t size,void *arg){
 (void)size;(void)arg;if(!dedicated.used){memset(&dedicated,0,sizeof dedicated);dedicated.used=dedicated.dedicated=true;return &dedicated;}return alloc_shared();
}
static int os_mbuf_appendfrom(struct os_mbuf *to,struct os_mbuf *from,unsigned offset,unsigned len){assert(from->used && to->used && offset+len<=from->len && to->len+len<=sizeof to->bytes);memcpy(to->bytes+to->len,from->bytes+offset,len);to->len+=len;return 0;}
static void os_mbuf_adj(struct os_mbuf *m,int len){assert(len>=0 && (unsigned)len<=m->len);m->len-=(unsigned)len;memmove(m->bytes,m->bytes+len,m->len);}
static struct os_mbuf *mem_split_frag(struct os_mbuf **m,unsigned max,struct os_mbuf *(*alloc)(uint16_t,void *),void *arg){
 if((*m)->len<=max){struct os_mbuf *out=*m;*m=NULL;return out;}struct os_mbuf *out=alloc((uint16_t)max,arg);if(!out)return NULL;os_mbuf_appendfrom(out,*m,0,max);os_mbuf_adj(*m,(int)max);return out;
}
static struct os_mbuf *ble_hs_hci_acl_hdr_prepend(struct os_mbuf *m,uint16_t handle,uint8_t pb){assert(handle==1 && m && m->used);m->pb=pb;return m;}
static int ble_hs_tx_data(struct os_mbuf *m){
 assert(m && m->used);
 if(transport_pressure && wire_fragments>=fail_after){os_mbuf_free_chain(m);return BLE_HS_ENOMEM;}
 assert(wire_size+m->len<=sizeof wire && wire_fragments<sizeof pbs);memcpy(wire+wire_size,m->bytes,m->len);wire_size+=m->len;pbs[wire_fragments++]=m->pb;os_mbuf_free_chain(m);return 0;
}
static struct os_mbuf *ble_l2cap_prepend_hdr(struct os_mbuf *m,uint16_t cid,unsigned len){assert(m && m->len==len);memmove(m->bytes+4,m->bytes,len);m->bytes[0]=(uint8_t)len;m->bytes[1]=(uint8_t)(len>>8);m->bytes[2]=(uint8_t)cid;m->bytes[3]=(uint8_t)(cid>>8);m->len+=4;return m;}
static int ble_hs_hci_acl_tx_now(struct ble_hs_conn *,struct os_mbuf **);
static int ble_hs_hci_acl_tx(struct ble_hs_conn *,struct os_mbuf **);
void ble_hs_wakeup_tx(void);
#if HAVE_RETRY_TIMER
void ble_hs_sched_tx_retry(void);
#endif
#include "production.inc"
static void reset(void){memset(shared,0,sizeof shared);memset(&dedicated,0,sizeof dedicated);memset(&connection,0,sizeof connection);connection.bhc_handle=1;STAILQ_INIT(&connection.bhc_tx_q);ble_hs_hci_avail_pkts=0;peak_shared=wire_size=wire_fragments=0;locked=transport_pressure=false;connection_live=true;clock_ticks=0;scheduled=BLE_HS_FOREVER;
#if HAVE_RETRY_TIMER
 ble_hs_tx_retry_pending=false;ble_hs_tx_retry_due=0;
#endif
}
static void queue_pattern(unsigned n,uint8_t seed,uint8_t *expected,unsigned *length){
 struct os_mbuf *m=alloc_shared();assert(m);for(unsigned i=0;i<n;i++)m->bytes[i]=(uint8_t)(seed+i*7);m->len=n;expected[(*length)++]=(uint8_t)n;expected[(*length)++]=(uint8_t)(n>>8);expected[(*length)++]=64;expected[(*length)++]=0;memcpy(expected+*length,m->bytes,n);*length+=n;struct ble_l2cap_chan ch={.dcid=64};ble_hs_lock();assert(!ble_l2cap_tx(&connection,&ch,m));ble_hs_unlock();
}
static void retry_after_release(void){
 transport_pressure=false;ble_hs_hci_avail_pkts=64;
#if HAVE_RETRY_TIMER
 clock_ticks=ble_hs_tx_retry_due;
#else
 clock_ticks+=10;
#endif
#if HAVE_RETRY_TIMER
 assert(ble_hs_tx_retry_timer()==BLE_HS_FOREVER);
#else
 ble_hs_wakeup_tx();
#endif
}
static void resource_failure(void){
 reset();uint8_t expected[1024];unsigned expected_size=0;queue_pattern(TEST_ACL_MAX==251?242:40,11,expected,&expected_size);queue_pattern(10,93,expected,&expected_size);assert(wire_size==0);
 ble_hs_hci_avail_pkts=64;transport_pressure=true;fail_after=TEST_ACL_MAX==251?0:1;ble_hs_wakeup_tx();
 #if HAVE_RETRY_TIMER
 assert(scheduled==10);unsigned before=wire_size;clock_ticks=9;
 assert(ble_hs_tx_retry_timer()==1 && wire_size==before);
#endif
 retry_after_release();
 assert(wire_size==expected_size && !memcmp(wire,expected,expected_size));
 unsigned first_len=(TEST_ACL_MAX==251?242:40)+4,first_frags=(first_len+TEST_ACL_MAX-1)/TEST_ACL_MAX;
 for(unsigned i=0;i<wire_fragments;i++)assert(pbs[i]==((i==0 || i==first_frags)?BLE_HCI_PB_FIRST_NON_FLUSH:BLE_HCI_PB_MIDDLE));
 assert(STAILQ_EMPTY(&connection.bhc_tx_q) && !(connection.bhc_flags&BLE_HS_CONN_F_TX_FRAG));
 for(unsigned i=0;i<8;i++)assert(!shared[i].used);assert(!dedicated.used);
}
/* Immediate transport pressure follows the same accepted/queued L2CAP path. */
static void immediate_pressure(void){
 reset();uint8_t expected[1024];unsigned expected_size=0;
 ble_hs_hci_avail_pkts=64;transport_pressure=true;fail_after=0;
 queue_pattern(20,7,expected,&expected_size);queue_pattern(16,45,expected,&expected_size);
 assert(!wire_size && !STAILQ_EMPTY(&connection.bhc_tx_q));
 retry_after_release();
 assert(wire_size==expected_size && !memcmp(wire,expected,expected_size));
 assert(STAILQ_EMPTY(&connection.bhc_tx_q) && !dedicated.used);
 for(unsigned i=0;i<8;i++)assert(!shared[i].used);
}
static void full_shared_pool(void){
 reset();uint8_t expected[1024];unsigned expected_size=0;queue_pattern(20,12,expected,&expected_size);queue_pattern(16,55,expected,&expected_size);
 struct os_mbuf *holders[8];unsigned held=0;struct os_mbuf *m;while((m=alloc_shared()))holders[held++]=m;
 struct os_mbuf *prior=ble_hs_hci_frag_alloc(8,NULL);assert(prior==&dedicated);ble_hs_hci_avail_pkts=64;ble_hs_wakeup_tx();
#if HAVE_RETRY_TIMER
 assert(!wire_size && !STAILQ_EMPTY(&connection.bhc_tx_q));
 clock_ticks=10;assert(ble_hs_tx_retry_timer()==10 && !wire_size);
#endif
 os_mbuf_free_chain(prior);retry_after_release();assert(wire_size==expected_size && !memcmp(wire,expected,expected_size));for(unsigned i=0;i<held;i++)os_mbuf_free_chain(holders[i]);assert(!dedicated.used);for(unsigned i=0;i<8;i++)assert(!shared[i].used);
}
static void ordinary_disconnect(void){
 reset();uint8_t expected[1024];unsigned expected_size=0;queue_pattern(20,33,expected,&expected_size);
 transport_pressure=true;fail_after=0;ble_hs_hci_avail_pkts=1;ble_hs_wakeup_tx();
 struct os_mbuf *m;while((m=STAILQ_FIRST(&connection.bhc_tx_q))){STAILQ_REMOVE_HEAD(&connection.bhc_tx_q,omp_next);os_mbuf_free_chain(m);}
 connection_live=false;
#if HAVE_RETRY_TIMER
 clock_ticks=ble_hs_tx_retry_due;assert(ble_hs_tx_retry_timer()==BLE_HS_FOREVER);
#endif
 assert(!wire_size && !dedicated.used);for(unsigned i=0;i<8;i++)assert(!shared[i].used);
}
int main(void){resource_failure();immediate_pressure();full_shared_pool();ordinary_disconnect();printf("actual SDK finite ACL queue pressure/release bytes+PB+ownership PASS max=%u\n",TEST_ACL_MAX);return 0;}
