"""Actual adapter functions: ordinary bounded SDU pressure, release and close."""
from pathlib import Path
import os, subprocess, tempfile
root=Path(__file__).resolve().parent.parent
source=(root/'src/wendy_ble_l2cap.c').read_text()
def function(name):
 start=source.index(name+'(');start=source.rfind('\n',0,start)+1
 begin=source.index('{',start);depth=1;end=begin+1
 while depth:
  depth+=(source[end]=='{')-(source[end]=='}');end+=1
 return source[start:end]+'\n'
functions=['_tx_backoff_expired','_arm_recv','_rx_rearm_host','_ring_append','_l2cap_event','_end_session_on_host','wble_l2cap_end_session','wble_l2cap_read']
head=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#define MTU 245
#define RING_SIZE (2*MTU)
#define TX_BACKOFF_MS 10
#define TX_SDU_MAX 245
#define CONFIG_WENDY_NET_TEST_DIAGNOSTICS 1
#define TAG "test"
#define ESP_LOGE(tag,...) do{if(0)fprintf(stderr,__VA_ARGS__);}while(0)
#define ESP_LOGI(tag,...) do{if(0)fprintf(stderr,__VA_ARGS__);}while(0)
#define ESP_LOGW(tag,...) do{if(0)fprintf(stderr,__VA_ARGS__);}while(0)
#define ESP_LOGD(tag,...) do{if(0)fprintf(stderr,__VA_ARGS__);}while(0)
#define ESP_OK 0
#define ESP_ERR_INVALID_STATE 1
#define BLE_HS_CONN_HANDLE_NONE UINT16_MAX
#define BLE_HS_ENOTCONN 7
#define BLE_ERR_REM_USER_CONN_TERM 19
#define portMAX_DELAY UINT32_MAX
#define BLE_HS_ENOMEM 6
#define BLE_HS_EBUSY 15
#define BLE_L2CAP_EVENT_COC_ACCEPT 1
#define BLE_L2CAP_EVENT_COC_CONNECTED 2
#define BLE_L2CAP_EVENT_COC_DISCONNECTED 3
#define BLE_L2CAP_EVENT_COC_DATA_RECEIVED 4
#define BLE_L2CAP_EVENT_COC_TX_UNSTALLED 5
#define OS_MBUF_PKTLEN(b) ((b)->len)
#define WBLE_ERR_WANT_READ -2
struct os_mbuf { bool owned;size_t len;uint8_t data[MTU]; };
struct ble_l2cap_chan {struct os_mbuf *rx;};
struct ble_l2cap_chan_info {uint16_t peer_coc_mtu,peer_l2cap_mtu;};
struct ble_l2cap_event {
 int type;
 struct {struct ble_l2cap_chan *chan;} accept;
 struct {int status;struct ble_l2cap_chan *chan;uint16_t conn_handle;} connect;
 struct {struct ble_l2cap_chan *chan;} disconnect;
 struct {struct os_mbuf *sdu_rx;struct ble_l2cap_chan *chan;} receive;
};
struct ble_npl_event {void (*callback)(struct ble_npl_event *);};
static struct ble_npl_event _rx_rearm_event, _end_event;
static bool _session_active, _disconnect_peer;
static uint16_t _session_peer;
static int _end_sem;
static void _end_session_on_host(struct ble_npl_event *);
static int xSemaphoreGive(int sem){(void)sem;return 1;}
static int xSemaphoreTake(int sem,unsigned timeout){(void)sem;(void)timeout;return 1;}
static int ble_gap_terminate(uint16_t handle,int reason){(void)handle;(void)reason;assert(false);return 0;}
static bool posted,timer_armed,allocation_pressure;
static unsigned allocs,frees,rearms;
static struct os_mbuf buffers[6];
static struct {unsigned mp_num_free;} _sdu_mempool={6};
static int _sdu_mbuf_pool,_tx_backoff_timer,_rx_sem,_tx_sem,_session_sem;
static struct ble_l2cap_chan *_chan;
static bool _rx_retry,_recv_ready_owed,_peer_gone,_tx_stalled,_tx_backoff;
static unsigned _tx_backoff_count;
static uint16_t _tx_mtu;
static size_t _ring_head,_ring_len;
static uint8_t _ring[RING_SIZE];
typedef int esp_err_t;
static void _lock(void){}
static void _unlock(void){}
static void _signal(int sem){(void)sem;}
static size_t _ring_free(void){return RING_SIZE-_ring_len;}
static void *nimble_port_get_dflt_eventq(void){return (void*)1;}
static void ble_npl_eventq_put(void *q,struct ble_npl_event *e){assert(q==(void*)1);if(e==&_end_event){_end_session_on_host(e);return;}assert(e==&_rx_rearm_event);posted=true;}
static int esp_timer_start_once(int timer,int us){(void)timer;assert(us==10000);if(timer_armed)return ESP_ERR_INVALID_STATE;timer_armed=true;return ESP_OK;}
static struct os_mbuf *os_mbuf_get_pkthdr(void *pool,int size){(void)pool;(void)size;if(allocation_pressure)return NULL;for(unsigned i=0;i<6;i++)if(!buffers[i].owned){buffers[i].owned=true;buffers[i].len=0;_sdu_mempool.mp_num_free--;allocs++;return &buffers[i];}return NULL;}
static void os_mbuf_free_chain(struct os_mbuf *p){assert(p && p->owned);p->owned=false;_sdu_mempool.mp_num_free++;frees++;}
static int ble_l2cap_recv_ready(struct ble_l2cap_chan *c,struct os_mbuf *p){if(c->rx)return BLE_HS_EBUSY;c->rx=p;rearms++;return 0;}
static int ble_l2cap_get_chan_info(struct ble_l2cap_chan *c,struct ble_l2cap_chan_info *i){(void)c;i->peer_coc_mtu=MTU;i->peer_l2cap_mtu=MTU;return 0;}
static void ble_l2cap_disconnect(struct ble_l2cap_chan *c){if(c->rx){os_mbuf_free_chain(c->rx);c->rx=NULL;}}
static int os_msys_num_free(void){return 12;}
static int os_msys_count(void){return 12;}
static void os_mbuf_copydata(struct os_mbuf *p,size_t off,size_t n,void *out){assert(off+n<=p->len);memcpy(out,p->data+off,n);}
'''
# Logs compile away in this fixture, so SDK diagnostic-only helpers may be unused.
body='\n'.join(function(n) for n in functions)
main=r'''
static void pump(void){if(posted){posted=false;_rx_rearm_event.callback(&_rx_rearm_event);}}
static void timer_fire(void){assert(timer_armed);timer_armed=false;_tx_backoff_expired(NULL);pump();}
static void connect_channel(struct ble_l2cap_chan *c){assert(!_arm_recv(c));struct ble_l2cap_event e={.type=BLE_L2CAP_EVENT_COC_CONNECTED};e.connect.chan=c;_l2cap_event(&e,NULL);}
static void receive(struct ble_l2cap_chan *c,const uint8_t *bytes,size_t n){assert(c->rx && n<=MTU);struct os_mbuf *p=c->rx;c->rx=NULL;memcpy(p->data,bytes,n);p->len=n;struct ble_l2cap_event e={.type=BLE_L2CAP_EVENT_COC_DATA_RECEIVED};e.receive.sdu_rx=p;e.receive.chan=c;_l2cap_event(&e,NULL);}
int main(void){
 _rx_rearm_event.callback=_rx_rearm_host;struct ble_l2cap_chan c={0};connect_channel(&c);
 uint8_t input[25646],output[25646];for(size_t i=0;i<sizeof input;i++)input[i]=(uint8_t)(i*17+3);
 size_t in=0,out=0;unsigned rounds=0;
 while(in<sizeof input){size_t n=sizeof input-in;if(n>MTU)n=MTU;
  if(!rounds){timer_armed=true;_tx_backoff=true;} /* shared pending TX timer */
  allocation_pressure=!(rounds++%7);receive(&c,input+in,n);in+=n;pump();
  if(allocation_pressure){assert(_recv_ready_owed && _rx_retry && !c.rx && timer_armed);allocation_pressure=false;timer_fire();assert(c.rx && !_recv_ready_owed && !_rx_retry && !_tx_backoff);}
  while(out<in){ssize_t got=wble_l2cap_read(output+out,(in-out)<73 ? in-out:73);assert(got>0);out+=(size_t)got;pump();}
 }
 assert(out==sizeof input && !memcmp(input,output,sizeof input));
 /* A full ring owes a receive until a reader makes one whole SDU free. */
 receive(&c,input,MTU);pump();receive(&c,input+MTU,MTU);assert(_recv_ready_owed && !posted && !c.rx);
 assert(wble_l2cap_read(output,73)==73);pump();assert(!c.rx);
 assert(wble_l2cap_read(output,200)==200);pump();assert(c.rx && !_recv_ready_owed);
 while(_ring_len)assert(wble_l2cap_read(output,sizeof output)>0);
 /* A second request cannot leak the SDK-refused caller-owned buffer. */
 _recv_ready_owed=true;unsigned before=frees;_rx_rearm_host(NULL);assert(!_recv_ready_owed && frees==before+1 && c.rx);
 allocation_pressure=true;receive(&c,input,10);pump();assert(_rx_retry && timer_armed);
 wble_l2cap_end_session(false);assert(!_chan && !_recv_ready_owed && !_rx_retry);
 allocation_pressure=false;unsigned old=allocs;timer_fire();assert(allocs==old && !posted);
 struct ble_l2cap_chan next={0};connect_channel(&next);pump();assert(next.rx && _chan==&next);
 wble_l2cap_end_session(false);assert(allocs==frees && _sdu_mempool.mp_num_free==6);
 assert(rearms>100);puts("Actual physical receive functions preserve25646 exact bytes across bounded pressure/release/backpressure/close and handle rearm ownership");return 0;
}
'''
with tempfile.TemporaryDirectory() as tmp:
 p=Path(tmp);(p/'test.c').write_text(head+body+main)
 subprocess.run([os.environ.get('CC','cc'),'-std=c11','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-parameter','-fsanitize=address,undefined',str(p/'test.c'),'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test')],check=True)
