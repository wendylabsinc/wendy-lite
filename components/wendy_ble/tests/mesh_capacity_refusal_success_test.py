"""Run the actual production native CoC callback at its physical capacity cap."""
from pathlib import Path
import os
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parent.parent
source = (root / 'src/wendy_ble_mesh.c').read_text()


def block(start):
    opening = source.index('{', start)
    depth, at = 1, opening + 1
    while depth:
        depth += (source[at] == '{') - (source[at] == '}')
        at += 1
    return source[start:at]


def function(name):
    match = re.search(r'(?m)^(?:static )?[^\n]*\b' + name + r'\([^;{}]*\)\s*\{', source)
    assert match, name
    return block(match.start())


pipe = block(source.index('struct wble_mesh_pipe {')) + ';'
initializer = function('initialize_host')
publication_start = re.search(
    r'if \(atomic_load\(&quiescing\)\)\s*return BLE_HS_EALREADY;\s*', initializer)
assert publication_start
publication = initializer[publication_start.end():initializer.index(
    '    atomic_store(&router_accepting', publication_start.end())]
fixture = r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include "wendy_net_profile.h"
#include "mesh_report_lifetime.h"
#define CHANNELS 3
#define MTU 245
#define TX_MAX 240
#define RX_SLOTS 1
#define CONFIG_WENDY_NET_BLE_PSM 129
#define WBLE_MESH_TIME_PSM 130
#define BLE_HS_EBUSY 1
#define BLE_HS_ENOMEM 2
#define BLE_L2CAP_EVENT_COC_ACCEPT 1
#define BLE_L2CAP_EVENT_COC_CONNECTED 2
#define BLE_L2CAP_EVENT_COC_DISCONNECTED 3
#define BLE_L2CAP_EVENT_COC_DATA_RECEIVED 4
#define BLE_L2CAP_EVENT_COC_TX_UNSTALLED 5
#define ESP_LOGD(...) ((void)0)
#define ESP_LOGI(...) ((void)0)
struct ble_l2cap_chan {int unused;};
struct ble_npl_event {int unused;};
struct os_mbuf {int unused;};
typedef void *SemaphoreHandle_t;
typedef struct {size_t bytes;} wendy_net_memory_reservation_t;
struct wble_mesh_peer {uint8_t address[6],address_type;uint16_t psm;bool server;};
struct ble_l2cap_event {
 int type;
 struct {struct ble_l2cap_chan *chan;uint16_t conn_handle;} accept,disconnect;
 struct {struct ble_l2cap_chan *chan;uint16_t conn_handle;int status;} connect;
 struct {struct ble_l2cap_chan *chan;struct os_mbuf *sdu_rx;} receive;
 struct {struct ble_l2cap_chan *chan;int status;} tx_unstalled;
};
struct ble_gap_conn_desc {struct {uint8_t type,val[6];} peer_ota_addr;};
struct ble_l2cap_chan_info {uint16_t peer_coc_mtu,peer_l2cap_mtu;};
''' + pipe + r'''
static atomic_bool ready,quiescing,router_accepting;
static atomic_uint router_capacity_refusals;
static struct wble_mesh_pipe *pipes[CHANNELS],*pending;
static struct wble_mesh_pipe spare;
static struct wble_report_lifetime report_lifetime;
#if !WENDY_NET_NON_TRANSIT
static struct wble_mesh_peer router_refusal_peer;
#endif
static bool held,allocation_ok,lock_available=true,desc_ok=true;
static uint8_t remote_hint=0x21;
static unsigned make_calls,arm_calls,wakes;
static void lock(void){assert(!held);held=true;}
static void unlock(void){assert(held);held=false;}
static bool trylock(void){if(!lock_available)return false;lock();return true;}
static void wake_actor(void){assert(!held);wakes++;}
static struct wble_mesh_pipe *make_pipe(struct ble_l2cap_chan *c,uint16_t h,bool server,uint16_t psm)
{
 assert(held);make_calls++;
 if(!allocation_ok)return NULL;
 for(unsigned i=0;i<CHANNELS;i++)if(!pipes[i]) {
  spare=(struct wble_mesh_pipe){.channel=c,.handle=h,.stack=true,.peer={.server=server,.psm=psm}};
  pipes[i]=&spare;return &spare;
 }
 assert(!"No physical allocation is allowed beyond CHANNELS");return NULL;
}
static int arm_receive_batch(struct wble_mesh_pipe *p,unsigned n)
{assert(p==&spare&&p->held&&!held&&n==RX_SLOTS);arm_calls++;return 0;}
static void retire(struct wble_mesh_pipe *p){assert(held&&p);}
static void reap_pool(void){assert(held);}
static int ble_gap_conn_find(uint16_t h,struct ble_gap_conn_desc *d)
{
 assert(h==7&&!held);
 if(!desc_ok)return -1;
 memset(d,0,sizeof *d);d->peer_ota_addr.type=1;d->peer_ota_addr.val[0]=remote_hint;
 return 0;
}
static int ble_l2cap_get_chan_info(struct ble_l2cap_chan *c,struct ble_l2cap_chan_info *i)
{(void)c;(void)i;assert(!"unexpected connection path");return -1;}
static int ble_gap_set_data_len(uint16_t h,unsigned n,unsigned t)
{(void)h;(void)n;(void)t;assert(!"unexpected connection path");return -1;}
static unsigned wble_mesh_profile(void){return 0;}
static struct wble_mesh_pipe *find(struct ble_l2cap_chan *c)
{(void)c;assert(!"unexpected connection path");return NULL;}
static void release_reserved_receive(struct wble_mesh_pipe *p){assert(p);}
static void notify(struct wble_mesh_pipe *p){assert(held&&p);}
static void post(struct wble_mesh_pipe *p){assert(held&&p);}
static void receive_data_locked(struct wble_mesh_pipe *p,struct os_mbuf *b){assert(held&&p&&b);}
static void os_mbuf_free_chain(struct os_mbuf *b){assert(b);}
static void close_pipe(struct wble_mesh_pipe *p){assert(held&&p);}
static int64_t esp_timer_get_time(void){return 1000000;}
''' + function('count') + r'''
#if !WENDY_NET_NON_TRANSIT
''' + function('note_capacity_refusal') + '\n' + function('wble_mesh_take_capacity_refusal') + r'''
static bool publication_observed;
static void observe_publication_open(struct wble_report_lifetime *lifetime)
{
 wble_report_open(lifetime);
 /* Run a normal actor pickup at the first possible instruction after ON's
  * publication opens. OFF's counter/row must already have been cleared. */
 struct wble_mesh_peer old={.psm=99};
 assert(!wble_mesh_take_capacity_refusal(&old)&&!old.psm);
 assert(!atomic_load(&router_capacity_refusals)&&!router_refusal_peer.psm);
 assert(!router_refusal_peer.address[0]&&wble_report_drained(lifetime));
 publication_observed=true;
}
#define wble_report_open(lifetime) observe_publication_open(lifetime)
static void initialize_receipt_publication(void)
{
''' + publication + r'''
}
#undef wble_report_open
#endif
''' + function('coc_event') + r'''
int main(void)
{
 struct ble_l2cap_chan channel={0};
 struct ble_l2cap_event event={.type=BLE_L2CAP_EVENT_COC_ACCEPT,.accept={.chan=&channel,.conn_handle=7}};
 void *native=(void *)(uintptr_t)CONFIG_WENDY_NET_BLE_PSM;
 assert(coc_event(&event,native)==BLE_HS_EBUSY&&!make_calls&&!arm_calls);
 ready=true;router_accepting=false;
#if WENDY_NET_NON_TRANSIT
 assert(coc_event(&event,native)==BLE_HS_EBUSY&&!make_calls&&!arm_calls&&!wakes);
 assert(!atomic_load(&router_capacity_refusals));(void)count;(void)wake_actor;
 (void)trylock;(void)report_lifetime;
 puts("Constrained native incoming still rejects without allocation or refusal-policy state");
#else
 struct wble_mesh_peer receipt={0};
 wble_report_open(&report_lifetime);
 assert(!wble_mesh_take_capacity_refusal(NULL));
 assert(!wble_mesh_take_capacity_refusal(&receipt));
 quiescing=true;assert(coc_event(&event,native)==BLE_HS_EBUSY&&!wakes);quiescing=false;
 assert(coc_event(&event,native)==BLE_HS_EBUSY&&wakes==1&&!make_calls&&!arm_calls);
 remote_hint=0x42;
 for(unsigned i=0;i<100;i++)assert(coc_event(&event,native)==BLE_HS_EBUSY);
 lock_available=false;assert(!wble_mesh_take_capacity_refusal(&receipt)&&!receipt.psm);
 assert(wble_report_drained(&report_lifetime)&&atomic_load(&router_capacity_refusals));
 lock_available=true;assert(wakes==1&&wble_mesh_take_capacity_refusal(&receipt));
 assert(receipt.psm==CONFIG_WENDY_NET_BLE_PSM&&receipt.address_type==1&&receipt.address[0]==0x21&&receipt.server);
 assert(!wble_mesh_take_capacity_refusal(&receipt));
 assert(coc_event(&event,(void *)(uintptr_t)WBLE_MESH_TIME_PSM)==BLE_HS_EBUSY);
 assert(coc_event(&event,(void *)(uintptr_t)1)==BLE_HS_EBUSY);
 assert(!wble_mesh_take_capacity_refusal(&receipt)&&wakes==1);
 struct wble_mesh_pipe owned[CHANNELS]={0};
 for(unsigned i=0;i<CHANNELS;i++){owned[i].owned=true;pipes[i]=&owned[i];}
 router_accepting=true;
 assert(coc_event(&event,native)==BLE_HS_ENOMEM&&count()==CHANNELS&&!make_calls&&!arm_calls);
 assert(wakes==2&&wble_mesh_take_capacity_refusal(&receipt)&&!wble_mesh_take_capacity_refusal(&receipt));
 assert(coc_event(&event,(void *)(uintptr_t)WBLE_MESH_TIME_PSM)==BLE_HS_ENOMEM);
 assert(!wble_mesh_take_capacity_refusal(&receipt)&&wakes==2);
 pipes[2]=NULL;allocation_ok=false;
 assert(coc_event(&event,native)==BLE_HS_ENOMEM&&make_calls==1&&!arm_calls);
 assert(!wble_mesh_take_capacity_refusal(&receipt)&&wakes==2); /* OOM below cap is not capacity demand */
 allocation_ok=true;
 assert(!coc_event(&event,native)&&make_calls==2&&arm_calls==1&&count()==CHANNELS&&!spare.held);
 assert(!wble_mesh_take_capacity_refusal(&receipt)&&wakes==2);
 assert(coc_event(&event,native)==BLE_HS_ENOMEM&&count()==CHANNELS&&make_calls==2);
 assert(wble_mesh_take_capacity_refusal(&receipt)&&wakes==3); /* a later retry produces a new receipt */
 desc_ok=false;
 assert(coc_event(&event,native)==BLE_HS_ENOMEM&&wakes==4);
 assert(wble_mesh_take_capacity_refusal(&receipt)&&!receipt.psm&&!receipt.address_type&&!receipt.address[0]);
 assert(wble_report_drained(&report_lifetime)&&!held);
 /* A receipt can survive OFF, but it must not cross ON's new publication. */
 wble_report_close(&report_lifetime);
 router_refusal_peer=(struct wble_mesh_peer){.address={0x99},.psm=CONFIG_WENDY_NET_BLE_PSM};
 atomic_store(&router_capacity_refusals,1);
 assert(!wble_mesh_take_capacity_refusal(&receipt)&&atomic_load(&router_capacity_refusals)==1);
 initialize_receipt_publication();assert(publication_observed);
 desc_ok=true;remote_hint=0x63;
 assert(coc_event(&event,native)==BLE_HS_ENOMEM&&wble_mesh_take_capacity_refusal(&receipt));
 assert(receipt.psm==CONFIG_WENDY_NET_BLE_PSM&&receipt.address[0]==0x63);
 puts("Native CoC full3: current accept stays rejected, one coalesced wake/receipt, no extra allocation, no OOM/time demand PASS");
#endif
}
'''
with tempfile.TemporaryDirectory(prefix='wendy-mesh-refusal-') as tmp:
    path = Path(tmp)
    (path / 'test.c').write_text(fixture)
    for constrained in (0, 1):
        binary = path / ('test' + str(constrained))
        subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                        '-DCONFIG_WENDY_NET_CONSTRAINED_PROFILE=' + str(constrained),
                        '-I' + str(root.parent / 'wendy_net_common/include'), '-I' + str(root / 'src'),
                        str(path / 'test.c'), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True)
        if constrained:
            symbols = subprocess.run(['nm', str(binary)], check=True, text=True, capture_output=True).stdout
            assert 'wble_mesh_take_capacity_refusal' not in symbols
            assert 'note_capacity_refusal' not in symbols
