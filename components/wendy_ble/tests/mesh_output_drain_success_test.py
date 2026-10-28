"""Run actual native stream/host effects through the local transmit fence."""
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


structure = block(source.index('struct wble_mesh_pipe\n')) + ';'
marker = 'else if (p && event->type == BLE_L2CAP_EVENT_COC_TX_UNSTALLED)'
unstalled = block(source.index(marker))
unstalled = unstalled[unstalled.index('{') + 1:-1]
fixture = r'''
#include <assert.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include "mesh_rx_window.h"
#define MTU 245
#define TX_MAX 240
#define RX_SLOTS 1
#define BLE_HS_ENOMEM 1
#define BLE_HS_ESTALLED 2
#define BLE_HS_EBUSY 3
#define BLE_HS_EBADDATA 4
#define BLE_HS_ENOTCONN 5
#define BLE_HS_EALREADY 6
#define BLE_ERR_REM_USER_CONN_TERM 7
#define ESP_LOGW(...) ((void)0)
struct ble_l2cap_chan {int id;};
struct ble_npl_event {void *argument;};
typedef void *SemaphoreHandle_t;
typedef struct {size_t bytes;} wendy_net_memory_reservation_t;
struct wble_mesh_peer {uint8_t address[6],address_type;uint16_t psm;bool server;};
''' + structure + r'''
static atomic_bool ready;
static void *mutex;
static bool lock_available=true,held;
static unsigned blocking_locks,posts,notifications,sends;
static int send_result;
static int64_t now=1000000;
static void lock(void){assert(!held);held=true;blocking_locks++;}
static bool trylock(void){if(!lock_available)return false;assert(!held);held=true;return true;}
static void unlock(void){assert(held);held=false;}
static int64_t esp_timer_get_time(void){return now;}
static void *ble_npl_event_get_arg(struct ble_npl_event *e){return e->argument;}
static void post(struct wble_mesh_pipe *p){assert(held);p->posted=true;posts++;}
static void notify(struct wble_mesh_pipe *p){assert(held);(void)p;notifications++;}
static void retire(struct wble_mesh_pipe *p){assert(held);(void)p;}
static void reap_pool(void){assert(held);}
static void close_pipe(struct wble_mesh_pipe *p){assert(held);p->closing=true;}
static bool wble_l2cap_uses_connection(uint16_t h){(void)h;assert(0);return false;}
static int ble_gap_terminate(uint16_t h,int reason){(void)h;(void)reason;assert(0);return 0;}
static int ble_l2cap_disconnect(struct ble_l2cap_chan *c){(void)c;assert(0);return 0;}
static int arm_receive_batch(struct wble_mesh_pipe *p,unsigned count){(void)p;(void)count;assert(0);return 0;}
struct os_mbuf {size_t size;uint8_t bytes[TX_MAX];};
static struct os_mbuf buffer;
static bool in_use;
static unsigned mbufs;
static struct os_mbuf *os_mbuf_get_pkthdr(void *pool,int flags)
{(void)pool;assert(!flags&&!in_use);in_use=true;mbufs++;buffer.size=0;return &buffer;}
static int os_mbuf_append(struct os_mbuf *b,const void *bytes,size_t size)
{assert(in_use&&b==&buffer&&size<=sizeof b->bytes);memcpy(b->bytes,bytes,size);b->size=size;return 0;}
static void os_mbuf_free_chain(struct os_mbuf *b){assert(in_use&&b==&buffer);in_use=false;}
static int ble_l2cap_send(struct ble_l2cap_chan *channel,struct os_mbuf *b)
{assert(channel&&in_use&&b==&buffer&&b->size==5&&!memcmp(b->bytes,"reply",5));sends++;
 if(send_result!=BLE_HS_EBUSY&&send_result!=BLE_HS_EBADDATA)in_use=false;
 return send_result;}
''' + function('pipe_event') + '\n' + function('stream_write') + '\n' + function('wble_mesh_output_drained') + r'''
static void unstalled(struct wble_mesh_pipe *p,int status)
{
 struct tx_event {struct {int status;} tx_unstalled;};
 struct tx_event notification={.tx_unstalled.status=status};
 struct tx_event *event=&notification;
 lock();
''' + unstalled + r'''
 unlock();
}
int main(void)
{
 struct ble_l2cap_chan channel={1};
 struct wble_mesh_pipe p={.owned=true,.connected=true,.stack=true,.channel=&channel,.tx_mtu=240};
 struct ble_npl_event event={.argument=&p};
 assert(!wble_mesh_output_drained(&p));ready=true;
 assert(!wble_mesh_output_drained(&p));mutex=&p;
 assert(!wble_mesh_output_drained(NULL));assert(wble_mesh_output_drained(&p));
 lock_available=false;assert(!wble_mesh_output_drained(&p));lock_available=true;
 p.connected=false;assert(!wble_mesh_output_drained(&p));p.connected=true;
 p.closing=true;assert(!wble_mesh_output_drained(&p));p.closing=false;
 p.owned=false;assert(!wble_mesh_output_drained(&p));p.owned=true;
 unsigned before=blocking_locks;
 assert(wble_mesh_output_drained(&p)&&blocking_locks==before);
 /* A positive actor write is only mailbox acceptance, not host submission. */
 assert(stream_write(&p,"reply",5)==5&&p.tx_pending);
 assert(!wble_mesh_output_drained(&p));
 send_result=BLE_HS_ENOMEM;pipe_event(&event);
 assert(p.tx_pending&&!wble_mesh_output_drained(&p));
 now+=10001;send_result=0;pipe_event(&event);
 assert(!p.tx_pending&&wble_mesh_output_drained(&p));
 /* NimBLE may retain an accepted SDU until credits arrive. */
 assert(stream_write(&p,"reply",5)==5);send_result=BLE_HS_ESTALLED;pipe_event(&event);
 assert(!p.tx_pending&&p.stalled&&!wble_mesh_output_drained(&p));
 unstalled(&p,0);assert(!p.stalled&&wble_mesh_output_drained(&p));
 assert(stream_write(&p,"reply",5)==5);send_result=BLE_HS_ESTALLED;pipe_event(&event);
 unstalled(&p,BLE_HS_ENOMEM);assert(p.tx_pending&&!p.stalled&&!wble_mesh_output_drained(&p));
 now+=10001;send_result=0;pipe_event(&event);assert(wble_mesh_output_drained(&p));
 assert(!in_use&&mbufs==sends&&posts&&notifications);
 puts("Native BLE send fence: mailbox, pressure, host acceptance, stalled credits and nonblocking readiness PASS");
}
'''
with tempfile.TemporaryDirectory(prefix='wendy-native-drain-') as tmp:
    path = Path(tmp)
    (path / 'test.c').write_text(fixture)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                    '-I' + str(root / 'src'), str(path / 'test.c'), '-o', str(path / 'test')], check=True)
    subprocess.run([str(path / 'test')], check=True)
