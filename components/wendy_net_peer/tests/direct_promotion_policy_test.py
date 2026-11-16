"""Run production automatic promotion policy against controlled route evidence."""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parent.parent
source = (root / 'src/peer.c').read_text()
start = source.index('static bool direct_promotion_target(')
end = source.index('bool wendy_net_peer_upper_blocked_now(', start)
fixture = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdatomic.h>
#include "wendy_net_direct_wire.h"
#define WN_DIRECT_PROMOTED 1
#define WNR_BLE_COST 1024
#define WN_BLE 1
struct wnrs {int unused;};
struct wb_route {uint64_t link;};
struct wn_direct_policy {bool operator_peer;struct {char peer[37];} identity;};
struct wn_direct_peer {
 struct wn_direct_peer *next;uint64_t serial;struct {uint8_t instance[16];} key;
 struct {unsigned count;} flows;
 struct {bool closed,attached,active;int mode;int64_t security_deadline;
  struct {int (*check)(void *,int64_t,int64_t *);unsigned selected;void *check_arg;} cfg;} session;
};
struct registry {struct wn_direct_peer *peers;unsigned count;};
struct peer_state {
 struct peer_state *next;struct registry direct_peers;int64_t direct_promotion_poll;
 atomic_bool active;void *connection,*operator_peer;bool failed;struct {bool cancel;} tls_state;
 char authenticated_peer[37];struct {int medium;uint16_t cost;} candidate;
};
static _Atomic(struct peer_state *) state;
static struct peer_state *selected;
static struct wnrs router;
static bool route_live=true,is_direct=true,policy_live=true,identity_current=true;
static int64_t clock_us=100;
static unsigned calls;
static int64_t esp_timer_get_time(void){return clock_us;}
static int wn_direct_policy_check(void *p,int64_t now,int64_t *deadline){(void)p;return policy_live&&now<*deadline?0:-1;}
static struct wn_direct_peer *wn_direct_registry_lookup(struct registry *r,uint64_t serial){return r->peers&&r->peers->serial==serial&&!r->peers->session.closed?r->peers:NULL;}
static struct wnrs *any_router(struct peer_state *r){(void)r;return &router;}
static bool wnrs_app_route(struct wnrs *r,const uint8_t *id,struct wb_route *route,uint16_t *port,bool *direct){
 (void)r;assert(id[0]==42);route->link=7;*port=43022;*direct=is_direct;return route_live;
}
static struct peer_state *route_link(struct peer_state *r,uint64_t link){(void)r;assert(link==7);return atomic_load(&selected->active)?selected:NULL;}
static bool identity_live(struct peer_state *p,int64_t now){(void)p;(void)now;return identity_current;}
static void wn_address(const uint8_t *id,uint8_t *address){memcpy(address,id,16);}
static int wn_app_direct_promote(uint64_t serial,const char *peer,const uint8_t *address,uint16_t port,bool (*eligible)(uint64_t,const uint8_t *,uint16_t)){
 assert(serial==3&&!strcmp(peer,"target")&&address[0]==42&&port==43022&&eligible(serial,address,port));calls++;return 0;
}
'''
fixture += source[start:end]
fixture += r'''
int main(void){
 uint8_t target[16]={42};
 struct wn_direct_policy policy={.identity={.peer="target"}};
 struct wn_direct_peer p={.serial=3,.key={.instance={42}},.flows={.count=1},
  .session={.security_deadline=10000000,.cfg={.selected=257,.check=wn_direct_policy_check,.check_arg=&policy}}};
 struct peer_state ble={.active=true,.connection=&p,.authenticated_peer="target",.candidate={WN_BLE,1024}};
 struct peer_state fast={.active=true,.connection=&p,.authenticated_peer="target",.candidate={2,128},.next=&ble};
 fast.direct_peers=(struct registry){.peers=&p,.count=1};state=&fast;selected=&fast;
 assert(direct_promotion_eligible(3,target,43022));assert(!direct_promotion_eligible(4,target,43022));
 p.session.cfg.selected|=WN_DIRECT_CAP_DATAGRAM_LIMIT;assert(direct_promotion_eligible(3,target,43022));
 assert(!direct_promotion_eligible(3,target,43023));target[1]=1;assert(!direct_promotion_eligible(3,target,43022));target[1]=0;
 assert(poll_direct_promotions(&fast,clock_us)==1&&calls==1);
 clock_us+=249999;assert(!poll_direct_promotions(&fast,clock_us)&&calls==1);
 clock_us++;assert(poll_direct_promotions(&fast,clock_us)==1&&calls==2);
 p.session.mode=WN_DIRECT_PROMOTED;p.session.attached=true;
 assert(direct_promotion_eligible(3,target,43022));clock_us+=250000;
 assert(!poll_direct_promotions(&fast,clock_us)&&calls==2);
 p.session.active=true;assert(!direct_promotion_eligible(3,target,43022));
 p.session.active=false;assert(direct_promotion_eligible(3,target,43022));p.session.mode=0;
 fast.candidate.cost=1024;assert(!direct_promotion_eligible(3,target,43022));fast.candidate.cost=128;
 selected=&ble;assert(!direct_promotion_eligible(3,target,43022));selected=&fast;
 route_live=false;assert(!direct_promotion_eligible(3,target,43022));route_live=true;
 policy.operator_peer=true;assert(!direct_promotion_eligible(3,target,43022));policy.operator_peer=false;
 p.flows.count=0;assert(!direct_promotion_eligible(3,target,43022));p.flows.count=1;
 is_direct=false;strcpy(fast.authenticated_peer,"relay");
 assert(!direct_promotion_eligible(3,target,43022)); /* BLE neighbor is still present. */
 ble.active=false;assert(direct_promotion_eligible(3,target,43022));
 route_live=false;assert(!direct_promotion_eligible(3,target,43022));route_live=true;
 fast.failed=true;assert(!direct_promotion_eligible(3,target,43022));fast.failed=false;
 fast.tls_state.cancel=true;assert(!direct_promotion_eligible(3,target,43022));fast.tls_state.cancel=false;
 fast.active=false;assert(!direct_promotion_eligible(3,target,43022));
 return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='wendy-direct-policy-') as directory:
    path = Path(directory)
    (path / 'test.c').write_text(fixture)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-I',str(root / 'include'),str(path / 'test.c'), '-o', str(path / 'test')], check=True)
    subprocess.run([str(path / 'test')], check=True)
print('automatic direct promotion policy passed')
