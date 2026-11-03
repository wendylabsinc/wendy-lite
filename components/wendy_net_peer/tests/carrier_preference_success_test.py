"""Preserve constrained actor preference across forwarding and identity loss.

The full profile's spare-capacity policy has its own actor fixture. This
fixture keeps the existing constrained path and both legacy Kconfig settings.
"""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parent.parent
source = Path(os.environ.get('WENDY_PEER_SOURCE', root / 'src/peer.c')).read_text()


def function(name):
    start = source.index(name + '(')
    start = source.rfind('\n', 0, start) + 1
    begin = source.index('{', start)
    depth, end = 1, begin + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end] + '\n'


head = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>
#include <string.h>
#define WN_LAN 0
#define WN_BLE 1
struct wn_candidate { unsigned medium; uint16_t cost, port; char address[64], device[37]; };
struct operator_peer { const char *principal; };
struct wnrs { int64_t forwarding_until; };
struct connection { bool borrowed; };
struct peer_state {
 struct peer_state *next;
 atomic_bool active, setup_pending;
 bool setup_waiting, failed;
 struct wn_candidate candidate;
 const struct operator_peer *operator_peer;
 uint8_t operator_instance[16];
 char authenticated_peer[37];
 int64_t identity_until;
 struct wnrs *router;
 struct connection *connection;
 struct { bool lent; } tls_state;
};
static int64_t clock_us = 100;
static unsigned retired;
static int64_t esp_timer_get_time(void) { return clock_us; }
static bool identity_live(struct peer_state *s, int64_t now) { return now < s->identity_until; }
/* This boundary is separately tested against the real signed directory,
 * installed FIB and Hello/IHU state in session_shared/session_pressure. */
bool wncrypto_borrowed(const struct connection *c) { return c && c->borrowed; }
bool wnrs_peer_forwarding_ready(const struct wnrs *s, int64_t now) {
 return s && now < s->forwarding_until;
}
static void retire_link(struct peer_state *s) {
 assert(atomic_exchange(&s->active, false)); retired++;
}
'''
main = r'''
static struct wnrs forwarding = {.forwarding_until = 1000};
static void initialize(struct peer_state *lan, struct peer_state *ble) {
 *lan = (struct peer_state){.next = ble, .active = true,
   .candidate = {.medium = WN_LAN, .cost = 128, .port = 43024, .device = "peer"},
   .identity_until = 1000, .router = &forwarding, .authenticated_peer = "peer"};
 *ble = (struct peer_state){.active = true,
   .candidate = {.medium = WN_BLE, .cost = 8192, .port = 129, .device = "peer"},
   .identity_until = 1000, .authenticated_peer = "peer"};
 retired = 0; forwarding.forwarding_until = 1000; clock_us = 100;
}
int main(void) {
 struct peer_state lan, ble;
 initialize(&lan, &ble);
 assert(same_peer(&lan, &ble) && identity_live(&lan, esp_timer_get_time()));
 (void)retire_link;
 struct wn_candidate hint = ble.candidate;
 if (CONFIG_WENDY_NET_KEEP_REDUNDANT_BLE) {
  assert(!cheaper_ip_carrier(&lan, &ble, NULL, 8192));
  atomic_store(&ble.active, false);
  assert(!candidate_used(&lan, &hint));
  atomic_store(&ble.active, true);
  prune_redundant_ble(&lan);
  assert(!retired && atomic_load(&ble.active));
  return 0;
 }
 /* The healthy exact same-peer forwarding path still vetoes a redundant dial. */
 atomic_store(&ble.active, false);
 assert(candidate_used(&lan, &hint));
 atomic_store(&ble.active, true);
 assert(cheaper_ip_carrier(&lan, &ble, NULL, 8192));
 /* A retained authenticated socket with expired routing reachability must
  * neither veto a new radio nor retire the existing working radio. */
 forwarding.forwarding_until = clock_us;
 atomic_store(&ble.active, false);
 assert(!candidate_used(&lan, &hint));
 atomic_store(&ble.active, true);
 prune_redundant_ble(&lan);
 assert(!retired && atomic_load(&ble.active));
 forwarding.forwarding_until = 1000;
 lan.identity_until = clock_us;
 assert(!cheaper_ip_carrier(&lan, &ble, NULL, 8192));
 prune_redundant_ble(&lan);
 assert(!retired && atomic_load(&ble.active));
 lan.identity_until = 1000;
 lan.failed = true;
 assert(!cheaper_ip_carrier(&lan, &ble, NULL, 8192));
 lan.failed = false;
 strcpy(lan.authenticated_peer, "different-peer");
 assert(!cheaper_ip_carrier(&lan, &ble, NULL, 8192));
 strcpy(lan.authenticated_peer, "peer");
 lan.candidate.cost = ble.candidate.cost;
 assert(!cheaper_ip_carrier(&lan, &ble, NULL, 8192));
 lan.candidate.cost = 128;
 hint.device[0] = 0; /* An unauthenticated discovery hint supplies no identity. */
 atomic_store(&ble.active, false);
 assert(!candidate_used(&lan, &hint));
 atomic_store(&ble.active, true);
 /* An operator's authenticated installation is part of exact peer matching. */
 const struct operator_peer op = {.principal = "same-tenant/operator/Alice"};
 lan.operator_peer = ble.operator_peer = &op;
 lan.operator_instance[0] = 1; ble.operator_instance[0] = 2;
 assert(!cheaper_ip_carrier(&lan, &ble, NULL, 8192));
 ble.operator_instance[0] = 1;
 assert(cheaper_ip_carrier(&lan, &ble, NULL, 8192));
 lan.operator_peer = ble.operator_peer = NULL;
 /* A preference decision must not record a deferred close while the radio
  * context is lent: the cheaper route can disappear before the loan returns. */
 struct connection loan = {.borrowed = true};
 ble.connection = &loan;
 prune_redundant_ble(&lan);
 assert(!retired && atomic_load(&ble.active));
 forwarding.forwarding_until = clock_us;
 loan.borrowed = false;
 prune_redundant_ble(&lan);
 assert(!retired && atomic_load(&ble.active));
 forwarding.forwarding_until = 1000;
 ble.tls_state.lent = true;
 prune_redundant_ble(&lan);
 assert(!retired && atomic_load(&ble.active));
 ble.tls_state.lent = false;
 ble.connection = NULL;
 /* Timer boundary is checked at the actor's current monotonic instant. */
 clock_us = 1000;
 prune_redundant_ble(&lan);
 assert(!retired && atomic_load(&ble.active));
 clock_us = 100;
 prune_redundant_ble(&lan);
 assert(retired == 1 && !atomic_load(&ble.active) && atomic_load(&lan.active));
 return 0;
}
'''
with tempfile.TemporaryDirectory() as tmp:
    p = Path(tmp)
    (p / 'test.c').write_text(head + function('same_peer') +
        function('cheaper_ip_carrier') + function('prune_redundant_ble') +
        function('candidate_used') + main)
    for keep in (0, 1):
        subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined',
                        '-DWENDY_NET_NON_TRANSIT=1',
                        '-DCONFIG_WENDY_NET_KEEP_REDUNDANT_BLE=' + str(keep),
                        str(p / 'test.c'), '-o', str(p / 'test')], check=True)
        subprocess.run([str(p / 'test')], check=True)
        print('carrier preference keep-redundant=' + str(keep) + ': PASS', flush=True)
