"""Exercise the production physical ownership query and release transitions."""
from pathlib import Path
import os
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parent.parent
source = (root / 'src/wendy_ble_mesh.c').read_text()
header = (root / 'include/wendy_ble_mesh.h').read_text()


def block(text, start):
    opening = text.index('{', start)
    depth, at = 1, opening + 1
    while depth:
        depth += (text[at] == '{') - (text[at] == '}')
        at += 1
    return text[start:at]


def function(name):
    match = re.search(r'(?m)^(?:static )?[^\n]*\b' + name + r'\([^;{}]*\)\s*\{', source)
    assert match, name
    return block(source, match.start())


pipe = block(source, source.index('struct wble_mesh_pipe {')) + ';'
capacity = block(header, header.index('struct wble_mesh_capacity {')) + ';'
query = function('wble_mesh_capacity_snapshot')
fixture = r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include "wendy_net_profile.h"
#include "mesh_gap_effect.h"
#include "mesh_report_lifetime.h"
#define CHANNELS 3
#define MYNEWT_VAL(x) 4
#define MTU 245
#define TX_MAX 240
#define RX_SLOTS 1
#define WBLE_MESH_TIME_PSM 130
struct ble_l2cap_chan {int unused;};
struct ble_npl_event {int unused;};
typedef void *SemaphoreHandle_t;
typedef struct {size_t bytes;} wendy_net_memory_reservation_t;
struct wble_mesh_peer {uint8_t address[6],address_type;uint16_t psm;bool server;};
''' + pipe + r'''
static struct wble_mesh_pipe *pipes[CHANNELS], *pending;
static struct wble_gap_retirement stopping_acls[MYNEWT_VAL(BLE_MAX_CONNECTIONS)];
static struct wble_report_lifetime report_lifetime;
static atomic_bool ready, quiescing;
static bool dialing, lock_available=true, held;
static uint16_t dial_psm;
static void *mutex;
static unsigned locks, unlocks, deletes, wakes;
static _Atomic(void (*)(void)) actor_wakeup;
static bool trylock(void){if(!lock_available)return false;assert(!held);held=true;locks++;return true;}
static void lock(void){assert(!held);held=true;locks++;}
static void unlock(void){assert(held);held=false;unlocks++;}
static void ble_npl_event_deinit(struct ble_npl_event *e){(void)e;deletes++;}
static void release_reserved_receive(struct wble_mesh_pipe *p){(void)p;}
static void vSemaphoreDelete(void *p){assert(p);deletes++;}
static void wendy_net_memory_release(wendy_net_memory_reservation_t *p){p->bytes=0;}
static void wendy_net_free(void *p){free(p);deletes++;}
static void notify(struct wble_mesh_pipe *p){assert(held);(void)p;}
static void post(struct wble_mesh_pipe *p){assert(held);p->posted=true;}
static void reap_pool(void){assert(held);}
static unsigned wble_rx_rearm_budget(unsigned a,unsigned b,size_t c,unsigned d)
{(void)a;(void)b;(void)c;(void)d;return 0;}
static int64_t esp_timer_get_time(void){return 1000000;}
static void wake(void){wakes++;}
''' + function('count') + '\n' + function('retire') + '\n' + function('close_pipe') + '\n' + function('retry') + '\n' + function('wble_mesh_release') + r'''
#if !WENDY_NET_NON_TRANSIT
static unsigned ready_reads;
static bool publish_on_second_read;
static bool snapshot_load(const atomic_bool *p)
{
 if(p==&ready&&publish_on_second_read&&++ready_reads==2) {
  atomic_store(&ready,true);wble_report_open(&report_lifetime);
 }
 return atomic_load_explicit(p,memory_order_seq_cst);
}
#undef atomic_load
#define atomic_load(p) snapshot_load(p)
''' + capacity + '\n' + query + r'''
#undef atomic_load
#define atomic_load(p) atomic_load_explicit(p,memory_order_seq_cst)
static struct wble_mesh_pipe *make(unsigned slot,unsigned psm,bool owned)
{
 struct wble_mesh_pipe *p=calloc(1,sizeof *p);assert(p);
 p->peer.psm=psm;p->owned=owned;p->stack=p->connected=true;p->wake=p;p->handle=(uint16_t)(slot+1);
 pipes[slot]=p;return p;
}
static void expect(unsigned external,unsigned retiring,bool physical,unsigned physical_free)
{
 struct wble_mesh_capacity c={.external=99,.retiring=99,.physical_free=99,.physical_ready=true};
 assert(wble_mesh_capacity_snapshot(&c));
 assert(c.external==external&&c.retiring==retiring&&c.physical_ready==physical&&c.physical_free==physical_free);
 assert(wble_report_drained(&report_lifetime)&&!held&&locks==unlocks);
}
int main(void)
{
 struct wble_mesh_capacity c={.external=99,.retiring=99,.physical_free=99,.physical_ready=true};
 assert(!wble_mesh_capacity_snapshot(NULL));
 assert(wble_mesh_capacity_snapshot(&c)&&!c.external&&!c.retiring&&!c.physical_ready&&!c.physical_free);
 /* Before ready, LAN has no native external owner and BLE cannot be dialed. */
 for(unsigned i=0;i<3;i++)expect(0,0,false,0);
 quiescing=true;assert(!wble_mesh_capacity_snapshot(&c));quiescing=false;
 publish_on_second_read=true;
 assert(!wble_mesh_capacity_snapshot(&c)); /* no stale empty snapshot across ready publication */
 assert(wble_report_drained(&report_lifetime));publish_on_second_read=false;
 wble_report_open(&report_lifetime);mutex=&mutex;ready=true;atomic_store(&actor_wakeup,wake);
 expect(0,0,true,3);
 lock_available=false;assert(!wble_mesh_capacity_snapshot(&c));
 assert(wble_report_drained(&report_lifetime));lock_available=true;
 quiescing=true;assert(!wble_mesh_capacity_snapshot(&c));quiescing=false;
 struct wble_mesh_pipe *actor=make(0,129,true);
 expect(0,0,true,2); /* actor carrier is already counted by its actor slot */
 struct wble_mesh_pipe *time=make(1,WBLE_MESH_TIME_PSM,false);
 expect(0,0,true,1); /* signed-time occupies physical, not native actor budget */
 struct wble_mesh_pipe *incoming=make(2,129,false);pending=incoming;
 expect(1,0,false,0); /* accepted pipe precedes actor ownership */
 incoming->owned=true;pending=NULL;expect(0,0,false,0);
 wble_mesh_release(actor);
 expect(1,1,false,0); /* actor pointer gone, before host sees release_requested */
 for(unsigned i=0;i<8;i++)expect(1,1,false,0); /* query never consumes teardown */
 retry(NULL);assert(!actor->owned&&actor->closing&&!atomic_load(&actor->release_requested));
 expect(1,1,false,0);
 actor->stack=actor->connected=actor->posted=false;actor->gap_owned=true;
 actor->gap_terminating=true;retire(actor);expect(1,1,false,0);
 /* Own GAP still pins this physical owner until the actual disconnect event. */
 actor->gap_owned=false;retire(actor);expect(0,0,true,1);assert(deletes==3&&wakes==1);
 dialing=true;dial_psm=129;expect(1,0,false,0);
 dial_psm=WBLE_MESH_TIME_PSM;expect(0,0,false,0);dialing=false;
 stopping_acls[0]=(struct wble_gap_retirement){.used=true,.handle=25};
 expect(1,1,true,1); /* pipe gone, independently tracked mesh-owned ACL stays charged */
 stopping_acls[0].handle=incoming->handle;expect(0,1,true,1); /* one handle, no duplicate external claim */
 stopping_acls[0].used=false;
 /* No management ACL is in pipes/stopping_acls; the query has no termination effect. */
 time->stack=time->connected=false;retire(time);expect(0,0,true,2);
 incoming->stack=incoming->connected=incoming->owned=false;retire(incoming);
 expect(0,0,true,3);assert(deletes==9&&wakes==3);
 wble_report_close(&report_lifetime);assert(!wble_mesh_capacity_snapshot(&c));
 puts("Native physical ownership: pending, release request, closing GAP, actual release and unknown snapshots PASS");
}
#else
int main(void)
{
 /* C6 has no policy-query code or additional persistent transport fields. */
 (void)pipes;(void)pending;(void)stopping_acls;(void)report_lifetime;(void)quiescing;
 (void)dialing;(void)dial_psm;(void)mutex;(void)trylock;(void)retire;(void)retry;
 (void)wble_mesh_release;(void)wake;(void)actor_wakeup;(void)count;
 printf("Constrained native pipe ABI: %zu bytes; capacity query compiled out\n",sizeof(struct wble_mesh_pipe));
}
#endif
'''
with tempfile.TemporaryDirectory(prefix='wendy-mesh-capacity-') as tmp:
    path = Path(tmp)
    (path / 'test.c').write_text(fixture)
    for constrained in (0, 1):
        binary = path / ('test' + str(constrained))
        subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                        '-DCONFIG_WENDY_NET_CONSTRAINED_PROFILE=' + str(constrained),
                        '-I' + str(root / 'src'), '-I' + str(root.parent / 'wendy_net_common/include'),
                        str(path / 'test.c'), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True)
        if constrained:
            symbols = subprocess.run(['nm', str(binary)], check=True, text=True, capture_output=True).stdout
            assert 'wble_mesh_capacity_snapshot' not in symbols
