"""Exercise actual mesh readiness and optional direct-time driver effects."""
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
#include <stdlib.h>
#include <stdio.h>
#define ESP_LOGI(...) ((void)0)
#define MALLOC_CAP_8BIT 0
#define ESP_OK 0
#define ESP_FAIL -1
#define TAG "test"
typedef int esp_err_t;
struct wendy_pki_mesh_identity { unsigned generation; };
struct time_bootstrap_job {
 atomic_bool done;
 bool submitted;
 esp_err_t result;
 int64_t started;
};
struct peer_state {
 bool clock_ready;
 int64_t clock_check_at, time_bootstrap_at;
 struct time_bootstrap_job *bootstrap_time;
};
static int64_t clock_us;
static int mesh_ready, public_time;
static bool wifi, configured, reset, worker_available, worker_accept, identity_current;
static unsigned allocated, freed, submitted, time_calls, identity_calls;
static void (*pending_work)(void *);
static void *pending_argument;
static int64_t esp_timer_get_time(void) { return clock_us; }
int wendy_pki_net_mesh_status(void) { return mesh_ready; }
static int wendy_pki_net_time_status(void) { return public_time; }
static bool wendy_wifi_is_connected(void) { return wifi; }
static bool wendy_conf_is_current(void) { return configured; }
static bool wendy_pki_reset_in_progress(void) { return reset; }
static bool wendy_pki_work_available(void) { return worker_available; }
static bool wendy_pki_mesh_identity_current(const struct wendy_pki_mesh_identity *id, int64_t now) {
 assert(id && now == clock_us); identity_calls++; return identity_current;
}
static esp_err_t wendy_pki_net_bootstrap_time(const void *stream) {
 assert(!stream); time_calls++; return public_time > 0 ? ESP_OK : ESP_FAIL;
}
static void *wendy_net_calloc(size_t n, size_t size) { allocated++; return calloc(n, size); }
static void wendy_net_free(void *p) { assert(p); freed++; free(p); }
static bool wendy_pki_io_work_submit(void (*work)(void *), void *argument) {
 submitted++; pending_work = work; pending_argument = argument; return worker_accept;
}
'''
main = r'''
static void defaults(void) {
 clock_us = 100;
 mesh_ready = 1; public_time = 0;
 wifi = reset = false; configured = worker_available = worker_accept = identity_current = true;
 allocated = freed = submitted = time_calls = identity_calls = 0;
 pending_work = NULL; pending_argument = NULL;
}
int main(int argc, char **argv) {
 assert(argc == 2); defaults();
 struct peer_state s = {0};
 struct wendy_pki_mesh_identity id = {1};
 if (!strcmp(argv[1], "offline")) {
  bootstrap_time_tick(&s, true);
  assert(s.clock_ready && !s.bootstrap_time && !allocated && !submitted);
  clock_us = 900000000; /* No five-minute public-proof lifetime for mesh identity. */
  assert(snapshot_live(&id, clock_us) && identity_calls == 1);
  identity_current = false;
  assert(!snapshot_live(&id, clock_us) && identity_calls == 2);
 } else if (!strcmp(argv[1], "separate")) {
  mesh_ready = 0; public_time = 1; wifi = true;
  bootstrap_time_tick(&s, true);
  assert(!s.clock_ready && !s.bootstrap_time && !allocated);
  mesh_ready = 1; public_time = 0; clock_us += 1000000;
  bootstrap_time_tick(&s, false); /* TLS setup owns admission, no direct HTTPS. */
  assert(s.clock_ready && !s.bootstrap_time && !allocated);
  mesh_ready = -1; clock_us += 1000000;
  bootstrap_time_tick(&s, false); /* A short identity-lock loan preserves readiness. */
  assert(s.clock_ready);
  mesh_ready = 0; clock_us += 1000000;
  bootstrap_time_tick(&s, false);
  assert(!s.clock_ready);
 } else if (!strcmp(argv[1], "direct")) {
  wifi = true;
  bootstrap_time_tick(&s, true);
  assert(s.clock_ready && s.bootstrap_time && allocated == 1 && !submitted);
  bootstrap_time_tick(&s, true);
  assert(submitted == 1 && s.bootstrap_time->submitted && pending_work);
  public_time = 1; pending_work(pending_argument);
  assert(time_calls == 1 && atomic_load(&s.bootstrap_time->done));
  bootstrap_time_tick(&s, true);
  assert(s.clock_ready && !s.bootstrap_time && freed == 1);
  clock_us += 20000000;
  bootstrap_time_tick(&s, true);
  assert(!s.bootstrap_time && allocated == 1); /* Already-fresh time never refetched. */
 } else if (!strcmp(argv[1], "failed")) {
  wifi = true;
  bootstrap_time_tick(&s, true);
  bootstrap_time_tick(&s, true);
  pending_work(pending_argument); /* Ordinary WAN failure does not revoke mesh. */
  bootstrap_time_tick(&s, true);
  assert(s.clock_ready && !s.bootstrap_time && freed == 1);
  bootstrap_time_tick(&s, true);
  assert(allocated == 1); /* Fixed retry delay, no busy retry. */
 } else if (!strcmp(argv[1], "deadline")) {
  wifi = true; worker_accept = false;
  bootstrap_time_tick(&s, true);
  bootstrap_time_tick(&s, true);
  assert(submitted == 1 && !s.bootstrap_time->submitted);
  clock_us += 30000001;
  bootstrap_time_tick(&s, true);
  assert(s.clock_ready && !s.bootstrap_time && freed == 1 && submitted == 1);
 } else assert(0);
 return 0;
}
'''
with tempfile.TemporaryDirectory() as tmp:
    p = Path(tmp)
    (p / 'test.c').write_text(head + '#include <string.h>\n' +
        function('release_time_job') + function('bootstrap_time_work') +
        function('bootstrap_time_tick') + function('snapshot_live') + main)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', str(p / 'test.c'), '-o', str(p / 'test')], check=True)
    for case in ('offline', 'separate', 'direct', 'failed', 'deadline'):
        subprocess.run([str(p / 'test'), case], check=True)
        print(case + ': PASS', flush=True)

# Exercise the actual lower-layer registration boundary too. The retired time
# PSM must not consume a listener or bypass ordinary router admission.
ble = Path(os.environ.get('WENDY_BLE_MESH_SOURCE',
                         root.parent / 'wendy_ble/src/wendy_ble_mesh.c')).read_text()
start = ble.index('static int initialize_host(void)')
end = ble.index('\nvoid wble_mesh_scan_interest', start)
ble_head = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#define ESP_OK 0
#define ESP_FAIL -1
#define BLE_HS_EALREADY 42
#define WBLE_MESH_TIME_PSM 130
#define CONFIG_WENDY_NET_BLE_PSM 129
#define MTU 1024
#define CHANNELS 4
#define SDUS 8
#define BLOCK 1024
#define INTERVAL_UNITS 12
#define MAX_CE_UNITS 12
#define MYNEWT_VAL(value) 1
#define OS_MEMPOOL_SIZE(n, size) 1
#define TAG "ble-test"
#define ESP_LOGI(tag, format, ...) do { (void)(tag); if (0) printf(format, __VA_ARGS__); } while (0)
#define ESP_LOGW(...) ((void)0)
static uint8_t own_type;
uint8_t pool_memory[1];
static int report_lifetime;
static atomic_bool quiescing, router_accepting, ready;
#if !WENDY_NET_NON_TRANSIT
struct wble_mesh_peer {
 uint8_t address[6], address_type;
 uint16_t psm;
 bool server;
};
static struct wble_mesh_peer router_refusal_peer;
static atomic_uint router_capacity_refusals;
#endif
static unsigned registrations;
static int register_error;
static int ble_hs_id_infer_auto(int preference, uint8_t *out) {
 assert(!preference); *out = 1; return 0;
}
static int coc_event(void *event, void *context) { (void)event; (void)context; return 0; }
static int ble_l2cap_create_server(unsigned psm, unsigned mtu,
                                  int (*callback)(void *, void *), void *context) {
 assert(psm == CONFIG_WENDY_NET_BLE_PSM && mtu == MTU && callback == coc_event);
 assert((uintptr_t)context == CONFIG_WENDY_NET_BLE_PSM);
 registrations++; return register_error;
}
static void wble_report_open(int *lifetime) { assert(lifetime == &report_lifetime); }
static unsigned wble_mesh_profile(void) { return 0; }
'''
ble_main = r'''
int main(void) {
 assert(initialize_host() == ESP_OK);
 assert(registrations == (WENDY_NET_NON_TRANSIT ? 0 : 1));
 assert(atomic_load(&ready) && atomic_load(&router_accepting) == !WENDY_NET_NON_TRANSIT);
 atomic_store(&ready, false);
 if (!WENDY_NET_NON_TRANSIT) {
  register_error = BLE_HS_EALREADY;
  assert(initialize_host() == ESP_OK && atomic_load(&ready));
  atomic_store(&ready, false);
  register_error = -7;
  assert(initialize_host() == ESP_FAIL && !atomic_load(&ready));
 }
 register_error = 0;
 atomic_store(&quiescing, true);
 assert(initialize_host() == BLE_HS_EALREADY);
 assert(!atomic_load(&ready));
 return 0;
}
'''
with tempfile.TemporaryDirectory() as tmp:
    p = Path(tmp)
    (p / 'ble.c').write_text(ble_head + ble[start:end] + ble_main)
    for constrained in (0, 1):
        subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', '-DWENDY_NET_NON_TRANSIT=' + str(constrained),
                        str(p / 'ble.c'), '-o', str(p / 'ble')], check=True)
        subprocess.run([str(p / 'ble')], check=True)
        print('BLE carrier-only registration, constrained=' + str(constrained) + ': PASS', flush=True)
