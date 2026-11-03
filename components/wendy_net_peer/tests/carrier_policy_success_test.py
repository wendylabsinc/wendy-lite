"""Exercise the production actor planner with real candidate and memory code.

Only owner, radio and routing effects are substituted. The policy functions,
candidate eligibility/order/backoff and charged allocator are production code.
The signed installed-route query is covered by session_shared/pressure.
"""
from pathlib import Path
import os
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parent.parent
source = Path(os.environ.get('WENDY_PEER_SOURCE', root / 'src/peer.c')).read_text()


def definition(name):
    match = re.search(r'^static [^;{}\n]*\b' + name + r'\([^;{}]*\)\s*\{', source, re.M)
    if not match:
        raise RuntimeError('missing production function ' + name)
    begin = source.index('{', match.start())
    depth, end = 1, begin + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[match.start():end] + '\n'


def structure(text, name):
    start = text.index('struct ' + name + ' {')
    return text[start:text.index('};', start) + 2] + '\n'


def incoming_pickup_gate():
    """Keep the exact actor's cached-standby gate ahead of TLS setup."""
    start = source.index('        if (pipe) {\n            hint = (struct wn_candidate){',
                         source.index('static void router_run('))
    begin = source.index('{', start)
    depth, end = 1, begin + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return r'''
static bool pickup_defers_standby(struct peer_state *root, struct wble_mesh_peer remote) {
    struct wn_candidate hint = {0};
    struct wble_mesh_pipe *pipe = (struct wble_mesh_pipe *)(uintptr_t)1;
    bool accepted = false;
''' + source[start:end] + r'''
    return accepted && !pipe;
}
'''


def setup_authentication_stage():
    """Execute the exact verified-TLS pickup/cache stage before hello I/O."""
    start = source.index('    if (!link->hello_started) {', source.index('static int setup_hello('))
    begin = source.index('{', start)
    depth, end = 1, begin + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    stage = source[start:end]
    assert stage.index('previously_authenticated_peer(') < stage.index('memcpy(link->authenticated_peer')
    assert stage.index('memcpy(link->authenticated_peer') < stage.index('wn_candidate_authenticated(')
    return 'static int setup_authenticated_stage(struct peer_state *link) {\n' + stage + '\nreturn 0;\n}\n'


head = r'''
#include "wendy_net_actor.h"
#include "wendy_net_peer_protocol.h"
#include "wendy_net_alloc.h"
#include <assert.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#define MALLOC_CAP_8BIT 1
#define ESP_LOGI(tag, ...) ((void)(tag), fixture_log(__VA_ARGS__))
#define ESP_LOGW(tag, ...) ((void)(tag), fixture_log(__VA_ARGS__))
#define ESP_LOGD(tag, ...) ((void)(tag), fixture_log(__VA_ARGS__))
#define ESP_OK 0
#define pdTRUE 1
#define WNR_BLE_COST 8192
static const char *TAG = "actor_fixture";
static void fixture_log(const char *format, ...) { (void)format; }
struct operator_peer { const char *principal; };
struct connection { bool borrowed; };
struct wnrs { int64_t forwarding_until; bool selected_routes; };
struct wnrs_node { unsigned unused; };
struct fixture_identity {
    char tenant[37], device[37], peer[37];
    int64_t verified_monotonic_us;
    uint64_t config_generation;
    uint8_t trust_hash[32], journal_trust_hash[32];
};
struct peer_state {
    struct { unsigned max_links, ble_links, wifi_links; bool ble, infrastructure_wifi; } config;
    struct peer_state *next, *owner;
    struct wn_selection *selection;
    struct wn_candidate candidate;
    atomic_bool active, setup_pending;
    atomic_uint carrier_count;
    bool candidate_held, setup_waiting, failed, clock_ready;
    struct { unsigned phase; } clock;
    struct wna_session tls_state;
    struct connection *connection;
    struct wnrs *router;
    struct wnrs_node *router_node;
    const struct operator_peer *operator_peer;
    uint8_t operator_instance[16];
    char authenticated_peer[37];
    uint64_t attachment;
    int64_t identity_until;
    struct fixture_identity identity;
    uint8_t self[16];
    int setup_result, candidate_index;
    bool setup_server, setup_have_stream;
    int64_t lease_us, refresh_at;
    void *bootstrap_time;
    bool ble_initialized, ble_published;
    struct wn_ble_scope ble_scope;
    uint8_t ble_advertisement[WN_BLE_ADVERTISEMENT_SIZE];
    void *ble_reports;
#if !WENDY_NET_NON_TRANSIT
    bool incoming_probe_waiting, setup_incoming_demand;
    int64_t incoming_probe_until_us;
#endif
    struct wna_channel *tls_channel;
    atomic_bool setup_complete;
    bool hello_started, setup_connecting;
    size_t hello_in, hello_out, hello_size;
    int setup_fd;
    int64_t setup_at;
    void *tls_setup;
    char control[64];
};
enum { CLOCK_EMPTY, CLOCK_RUNNING };
#define REFRESH_INTERVAL_US 1000000
#define PEER_CONTROL_BYTES 64
static pthread_mutex_t state_lock = PTHREAD_MUTEX_INITIALIZER;
static int64_t clock_us;
static size_t free_heap;
static unsigned mesh_limit, snapshots, retired;
static unsigned refusal_reads;
static bool capacity_refused;
static unsigned advertisement_publishes;
static uint8_t written_capabilities, published_capabilities;
static bool snapshot_ok, delay_release;
static struct peer_state *last_retired;
static int64_t esp_timer_get_time(void) { return clock_us; }
static uint32_t esp_random(void) { return 42; }
static size_t heap_caps_get_free_size(unsigned caps) { assert(caps == MALLOC_CAP_8BIT); return free_heap; }
static unsigned wendy_pki_handshake_mesh_limit(void) { return mesh_limit; }
static bool identity_live(struct peer_state *s, int64_t now) { return now < s->identity_until; }
static bool wncrypto_borrowed(const struct connection *c) { return c && c->borrowed; }
static bool wnrs_peer_forwarding_ready(const struct wnrs *s, int64_t now) {
    return s && now < s->forwarding_until;
}
static bool wnrs_reclaim_idle(const struct wnrs *s, int64_t now) {
    (void)now; return s && !s->selected_routes;
}
static bool wnrs_node_busy(const struct wnrs_node *n) { (void)n; return false; }
static uint64_t wnrs_link_id(const struct wnrs *s) { assert(s); return 1; }
static int router_send(void *context, const void *data, size_t size, bool control) {
    (void)context; (void)data; (void)size; (void)control; return 0;
}
static struct wnrs opened_route;
static struct connection *verified_connection;
static struct fixture_identity verified_identity;
static const struct operator_peer *verified_operator;
static unsigned opens;
static unsigned operator_opens;
static bool open_succeeds;
static int wnrs_open(struct wnrs **out, void *owner, struct connection *connection,
                     const void *identity, const void *peer, unsigned cost,
                     int (*send)(void *, const void *, size_t, bool), void *context) {
    (void)owner; (void)identity; (void)peer; (void)cost;
    assert(connection && send == router_send && context);
    if (!open_succeeds) return -1;
    *out = &opened_route; opens++; return 0;
}
static int wnrs_open_operator(struct wnrs **out, void *owner, struct connection *connection,
                              const void *identity, const void *peer, unsigned cost,
                              int (*send)(void *, const void *, size_t, bool), void *context) {
    operator_opens++;
    return wnrs_open(out, owner, connection, identity, peer, cost, send, context);
}
static int reserve_candidate(struct peer_state *s, const struct wn_candidate *c) {
    int index = wn_candidate_seen(s->selection, c, clock_us / 1000);
    if (index < 0) return -1;
    if (s->candidate_held && s->candidate_index == index) return index;
    if (wn_candidate_hold(s->selection, (unsigned)index)) return -1;
    if (s->candidate_held && s->candidate_index >= 0)
        wn_candidate_release(s->selection, (unsigned)s->candidate_index);
    s->candidate_held = true;
    s->candidate_index = index;
    return index;
}
/* Discovery syntax only. It never supplies the proof stub above. */
int wn_uuid_parse(const char *text, uint8_t out[16]) {
    if (!text || strlen(text) != 36) return -1;
    memset(out, 0, 16); return 0;
}
'''

effects = r'''
static struct wble_mesh_capacity physical;
static struct wble_mesh_peer refused_peer;
static bool wble_mesh_capacity_snapshot(struct wble_mesh_capacity *out) {
    snapshots++;
    if (!snapshot_ok) return false;
    *out = physical; return true;
}
static bool wble_mesh_take_capacity_refusal(struct wble_mesh_peer *out) {
    bool refused = capacity_refused;
    capacity_refused = false;
    refusal_reads++;
    *out = refused_peer;
    return refused;
}
static bool wble_mesh_incoming_available(void) { return physical.physical_ready; }
static int wble_mesh_poll_error(unsigned *operation) { *operation = 0; return 0; }
static int wble_mesh_init(void) { return ESP_OK; }
static bool wendy_conf_is_current(void) { return true; }
static bool wendy_pki_reset_in_progress(void) { return false; }
int wn_ble_default_scope_init(struct wn_ble_scope *scope, const char *tenant) {
    assert(tenant); memset(scope, 0, sizeof *scope); return 0;
}
int wn_ble_adv_write_capabilities(const struct wn_ble_scope *scope, const char *device,
                                  uint16_t psm, uint8_t capabilities,
                                  uint8_t out[WN_BLE_ADVERTISEMENT_SIZE]) {
    assert(scope && device && psm == CONFIG_WENDY_NET_BLE_PSM);
    memset(out, 0, WN_BLE_ADVERTISEMENT_SIZE);
    out[22] = written_capabilities = capabilities;
    return WN_BLE_ADVERTISEMENT_SIZE;
}
static int wendy_ble_mesh_advertisement(const uint8_t *data, size_t size) {
    advertisement_publishes++;
    if (data) { assert(size == WN_BLE_ADVERTISEMENT_SIZE); published_capabilities = data[22]; }
    return ESP_OK;
}
static void ble_report(void) {}
static int wble_mesh_scan(void (*report)(void), void *context) {
    assert(report == ble_report && context); return ESP_OK;
}
static int xQueueReceive(void *queue, void *report, unsigned timeout) {
    (void)queue; (void)report; assert(!timeout); return 0;
}
static int planned_candidate(struct peer_state *s, const struct wn_candidate *c,
                             const char *device, const uint8_t *hint, int64_t now) {
    (void)s; (void)c; (void)device; (void)hint; (void)now;
    assert(!"the no-hint actor fixture must not create a discovery row"); return -1;
}
static void retire_link(struct peer_state *s) {
    /* The actor policy has to establish the safe boundary before this effect. */
    assert(atomic_load(&s->active) && !s->failed && !s->tls_state.cancel &&
           !s->tls_state.lent && !wncrypto_borrowed(s->connection));
    retired++; last_retired = s;
    atomic_store(&s->active, false);
    atomic_fetch_sub(&(s->owner ? s->owner : s)->carrier_count, 1);
    s->connection = NULL;
    s->router = NULL;
    s->attachment++;
    if (s->candidate_held && s->candidate_index >= 0) {
        wn_candidate_release(s->selection, (unsigned)s->candidate_index);
        s->selection->candidates[s->candidate_index].retry_ms = clock_us / 1000 + 5000;
    }
    s->candidate_held = false;
    if (s->candidate.medium == WN_BLE && delay_release) {
        physical.external++;
        physical.retiring++;
        physical.physical_ready = false;
    } else if (s->candidate.medium == WN_BLE) {
        physical.physical_free++;
    }
}
static unsigned wble_mesh_profile(void) { return 0; }
static struct connection *wendy_pki_net_take(void *setup, struct fixture_identity *identity) {
    (void)setup; assert(verified_connection);
    *identity = verified_identity; return verified_connection;
}
static const struct operator_peer *wendy_pki_mesh_authenticated_operator(struct connection *c) {
    assert(c); return verified_operator;
}
static void wnad_handshake_release(struct peer_state *link) { assert(link); }
int wn_router_hello_write(const char *self, const char *peer, char *out, size_t capacity) {
    assert(self && peer && capacity); *out = 1; return 1;
}
void wn_put32(uint8_t *out, uint32_t value) {
    for (unsigned i = 0; i < 4; i++) out[i] = (uint8_t)(value >> (24 - 8 * i));
}
static int wnad_connect(const char *address, unsigned port, bool *connecting) {
    assert(address && port); *connecting = true; return 7;
}
static bool wnad_prepare_socket(int fd) { return fd >= 0; }
static int close(int fd) { assert(fd >= 0); return 0; }
struct wble_mesh_pipe;
static unsigned gate_releases;
static void wble_mesh_release(struct wble_mesh_pipe *pipe) { assert(pipe); gate_releases++; }
'''

main = r'''
static const char *peer_a = "10000000-0000-4000-8000-000000000001";
static const char *peer_b = "20000000-0000-4000-8000-000000000002";
static const char *peer_c = "30000000-0000-4000-8000-000000000003";
struct fixture {
    struct peer_state links[8];
    struct connection connections[8];
    struct wnrs routes[8];
    struct wn_selection selection;
};
static struct peer_state *reset(struct fixture *f) {
    memset(f, 0, sizeof *f);
    wn_selection_init(&f->selection);
    unsigned count = WENDY_NET_NON_TRANSIT ? 1 : 8;
    for (unsigned i = 0; i < count; i++) {
        f->links[i].selection = &f->selection;
        f->links[i].owner = i ? &f->links[0] : NULL;
        f->links[i].candidate_index = -1;
        f->links[i].attachment = 10 + i;
        if (i + 1 < count) f->links[i].next = &f->links[i + 1];
    }
    f->links[0].config.max_links = count;
    f->links[0].config.ble_links = WENDY_NET_NON_TRANSIT ? 1 : 3;
    f->links[0].config.wifi_links = count;
    f->links[0].config.ble = true;
    f->links[0].config.infrastructure_wifi = !WENDY_NET_NON_TRANSIT;
    f->links[0].clock_ready = true;
    clock_us = 1000000;
    free_heap = CONFIG_WENDY_NET_SETUP_FREE_BYTES;
    mesh_limit = 1;
    snapshots = retired = opens = operator_opens = refusal_reads = 0;
    open_succeeds = true;
    capacity_refused = false;
    verified_connection = NULL;
    verified_operator = NULL;
    memset(&verified_identity, 0, sizeof verified_identity);
    refused_peer = (struct wble_mesh_peer){0};
    gate_releases = 0;
    advertisement_publishes = 0;
    written_capabilities = published_capabilities = 0;
    last_retired = NULL;
    snapshot_ok = true;
    delay_release = false;
    physical = (struct wble_mesh_capacity){.physical_ready = true, .physical_free = 3};
    return &f->links[0];
}
static void own(struct fixture *f, unsigned i, const char *peer, enum wn_medium medium,
                unsigned cost, bool forwarding) {
    struct peer_state *s = &f->links[i];
    s->candidate = (struct wn_candidate){.medium = medium, .cost = cost,
                                        .port = medium == WN_BLE ? 129 : 43024};
    snprintf(s->candidate.address, sizeof s->candidate.address, "owner-%u", i);
    strcpy(s->candidate.device, peer);
    strcpy(s->authenticated_peer, peer);
    s->active = true;
    s->candidate_held = true;
    s->connection = &f->connections[i];
    s->router = &f->routes[i];
    s->identity_until = clock_us + 100000000;
    f->routes[i].forwarding_until = forwarding ? s->identity_until : 0;
    if (medium == WN_BLE) { assert(physical.physical_free); physical.physical_free--; }
    atomic_fetch_add(&f->links[0].carrier_count, 1);
}
static int hint(struct fixture *f, unsigned serial, const char *peer, enum wn_medium medium,
                unsigned cost) {
    struct wn_candidate c = {.medium = medium, .cost = cost,
        .port = medium == WN_BLE ? 129 : 43024,
        .ble_capabilities = WN_BLE_NATIVE_ACCEPTING};
    snprintf(c.address, sizeof c.address, "hint-%u", serial);
    if (peer) strcpy(c.device, peer);
    int index = wn_candidate_seen(&f->selection, &c, clock_us / 1000);
    assert(index >= 0);
    return index;
}
static void full_redundant(struct fixture *f) {
    reset(f);
    own(f, 0, peer_a, WN_LAN, 128, true);
    own(f, 1, peer_a, WN_BLE, 8192, false);
    for (unsigned i = 2; i < 8; i++) {
        char peer[37];
        snprintf(peer, sizeof peer, "40000000-0000-4000-8000-%012u", i);
        own(f, i, peer, WN_LAN, 128, true);
    }
}
static void assert_no_allocations(void) {
    wendy_net_memory_snapshot_t m;
    wendy_net_runtime_memory_snapshot(&m);
    assert(!m.current_bytes && !m.allocation_count);
}
static void constrained(void) {
    struct fixture f;
    struct peer_state *root = reset(&f);
    assert(slot_free(root) && capacity_available(root) && medium_available(root, WN_BLE));
    int radio = hint(&f, 0, NULL, WN_BLE, 8192);
    assert(additional_candidate(root, clock_us / 1000, true) == radio);
    own(&f, 0, peer_a, WN_BLE, 8192, false);
    assert(!capacity_available(root) && !medium_available(root, WN_BLE));
    assert(additional_candidate(root, clock_us / 1000, true) == -1);
    root->active = false;
    assert(!slot_free(root)); /* Cleanup ownership still consumes the sole slot. */
    root->candidate_held = false;
    root->connection = NULL;
    root->clock.phase = CLOCK_RUNNING;
    assert(!slot_free(root));
    root->clock.phase = CLOCK_EMPTY;
    assert(slot_free(root) && medium_available(root, WN_BLE));
    assert(!snapshots && !retired);
    assert(!refusal_reads);
    update_ble(root, peer_a, peer_a);
    assert(!written_capabilities && !root->ble_published && !advertisement_publishes);
    assert(!snapshots && !refusal_reads);
    assert_no_allocations();
}
#if !WENDY_NET_NON_TRANSIT
static void priority_and_aliases(void) {
    struct fixture f;
    struct peer_state *root = reset(&f);
    own(&f, 0, peer_a, WN_BLE, 8192, true);
    int fast = hint(&f, 0, peer_a, WN_LAN, 128);
    int newcomer = hint(&f, 1, peer_b, WN_BLE, 8192);
    assert(candidate_class(root, &f.selection.candidates[fast]) == 1);
    assert(candidate_class(root, &f.selection.candidates[newcomer]) == 0);
    assert(additional_candidate(root, clock_us / 1000, true) == newcomer);
    f.selection.candidates[newcomer].passive = true;
    assert(additional_candidate(root, clock_us / 1000, true) == fast);
    f.selection.candidates[newcomer].passive = false;
    wn_candidate_failed(&f.selection, (unsigned)newcomer, clock_us / 1000);
    assert(additional_candidate(root, clock_us / 1000, true) == fast);
    f.selection.candidates[newcomer].retry_ms = 0;
    assert(!wn_candidate_hold(&f.selection, (unsigned)newcomer));
    assert(additional_candidate(root, clock_us / 1000, true) == fast);
    wn_candidate_release(&f.selection, (unsigned)newcomer);
    f.selection.candidates[newcomer].seen_ms = clock_us / 1000 - 30000;
    assert(additional_candidate(root, clock_us / 1000, true) == fast);
    struct wn_candidate alias = root->candidate;
    strcpy(alias.address, "another-address");
    assert(candidate_used(root, &alias)); /* Learned same-medium UUID alias. */
    alias.device[0] = 0;
    strcpy(alias.address, root->candidate.address);
    assert(candidate_used(root, &alias)); /* Unknown identity, same endpoint. */
    alias.medium = WN_LAN;
    assert(!candidate_used(root, &alias));
    own(&f, 1, peer_a, WN_LAN, 128, true);
    assert(atomic_load(&f.links[0].active) && atomic_load(&f.links[1].active));
    assert(!reclaim_victim(root, WN_BLE)); /* Spare capacity retains standby. */
    struct wn_candidate standby = {.medium = WN_BLE, .cost = 8192};
    strcpy(standby.device, peer_a);
    assert(candidate_class(root, &standby) == 2);
    standby.cost = 512; /* The cheapest owner determines upgrade priority. */
    assert(candidate_class(root, &standby) == 2);
    assert_no_allocations();
}

static void authenticated_admission(void) {
    struct fixture f;
    struct peer_state *root = reset(&f), *radio = &f.links[1];
    own(&f, 0, peer_a, WN_BLE, 8192, true);
    radio->candidate = (struct wn_candidate){.medium = WN_LAN, .cost = 128,
                                            .port = 43024, .address = "faster-lan"};
    radio->connection = &f.connections[1];
    radio->identity_until = clock_us + 100000000;
    strcpy(radio->authenticated_peer, peer_a);
    strcpy(radio->identity.device, "00000000-0000-4000-8000-000000000000");
    opened_route.forwarding_until = 0;
    assert(admit_link(root, radio) == 0);
    assert(opens == 1 && !retired && atomic_load(&root->active) && atomic_load(&radio->active));
    assert(wnrs_peer_forwarding_ready(root->router, clock_us));
    assert(!wnrs_peer_forwarding_ready(radio->router, clock_us));
    root = reset(&f); radio = &f.links[1];
    own(&f, 0, peer_a, WN_LAN, 128, true);
    radio->candidate = (struct wn_candidate){.medium = WN_BLE, .cost = 8192,
                                            .port = 129, .address = "new-radio"};
    radio->connection = &f.connections[1];
    radio->identity_until = clock_us + 100000000;
    strcpy(radio->authenticated_peer, peer_a);
    strcpy(radio->identity.device, "00000000-0000-4000-8000-000000000000");
    assert(admit_link(root, radio) == 0);
    assert(opens == 1 && !retired && atomic_load(&root->active) && atomic_load(&radio->active));
    /* Authentication can reveal that an unknown probe is the same-medium alias
     * of an existing owner. Production admission retains that incumbent. */
    struct peer_state *alias = &f.links[2];
    alias->candidate = (struct wn_candidate){.medium = WN_BLE, .cost = 8192,
                                            .port = 129, .address = "another-radio"};
    alias->connection = &f.connections[2];
    alias->identity_until = clock_us + 100000000;
    strcpy(alias->authenticated_peer, peer_a);
    strcpy(alias->identity.device, radio->identity.device);
    assert(admit_link(root, alias) == -1);
    assert(opens == 1 && !retired && atomic_load(&radio->active) && !atomic_load(&alias->active));
    assert_no_allocations();
}

static void reclaim_boundaries(void) {
    struct fixture f;
    full_redundant(&f);
    struct peer_state *root = &f.links[0], *victim = &f.links[1];
    int probe = hint(&f, 0, NULL, WN_BLE, 8192);
    assert(candidate_class(root, &f.selection.candidates[probe]) == 0);
    assert(reclaim_victim(root, WN_BLE) == victim);
    assert(ble_discovery_available(root));
    /* A ready peer /128 on the survivor does not prove that the slower victim
     * is idle: a selected installed transit route still requires that owner. */
    assert(wnrs_peer_forwarding_ready(root->router, clock_us));
    f.routes[1].selected_routes = true;
    assert(!reclaim_victim(root, WN_BLE));
    assert(plan_additional_candidate(root, clock_us / 1000, true) == -1 && !retired);
    f.routes[1].selected_routes = false;
    assert(reclaim_victim(root, WN_BLE) == victim);
    /* Every condition is checked on the current owner on each actor turn. */
    victim->tls_state.lent = true;
    assert(!reclaim_victim(root, WN_BLE));
    victim->tls_state.lent = false;
    f.connections[1].borrowed = true;
    assert(!reclaim_victim(root, WN_BLE));
    f.routes[0].forwarding_until = clock_us;
    f.connections[1].borrowed = false;
    assert(plan_additional_candidate(root, clock_us / 1000, true) == -1);
    assert(!retired && !victim->tls_state.cancel && !victim->failed);
    f.routes[0].forwarding_until = clock_us + 100000000;
    victim->tls_state.cancel = true;
    assert(!reclaim_victim(root, WN_BLE));
    victim->tls_state.cancel = false;
    victim->failed = true;
    assert(!reclaim_victim(root, WN_BLE));
    victim->failed = false;
    f.routes[0].forwarding_until = clock_us;
    assert(!reclaim_victim(root, WN_BLE));
    f.routes[0].forwarding_until = clock_us + 100000000;
    root->identity_until = clock_us;
    assert(!reclaim_victim(root, WN_BLE));
    root->identity_until = clock_us + 100000000;
    root->tls_state.cancel = true;
    assert(!reclaim_victim(root, WN_BLE));
    root->tls_state.cancel = false;
    root->failed = true;
    assert(!reclaim_victim(root, WN_BLE));
    root->failed = false;
    f.connections[0].borrowed = true;
    assert(!reclaim_victim(root, WN_BLE));
    f.connections[0].borrowed = false;
    root->tls_state.lent = true;
    assert(!reclaim_victim(root, WN_BLE));
    root->tls_state.lent = false;
    f.links[7].setup_waiting = true;
    assert(!reclaim_victim(root, WN_BLE));
    f.links[7].setup_waiting = false;
    f.links[7].active = false;
    f.links[7].clock.phase = CLOCK_RUNNING;
    assert(!reclaim_victim(root, WN_BLE));
    f.links[7].active = true;
    f.links[7].clock.phase = CLOCK_EMPTY;
    snapshot_ok = false;
    assert(!reclaim_victim(root, WN_BLE));
    snapshot_ok = true;
    physical.physical_ready = false;
    assert(reclaim_victim(root, WN_BLE) == victim);
    physical.physical_ready = true;
    physical.retiring = 1;
    assert(!reclaim_victim(root, WN_BLE));
    physical.retiring = 0;
    const struct operator_peer op = {.principal = "tenant/operator/Alice"};
    root->operator_peer = victim->operator_peer = &op;
    root->operator_instance[0] = 1;
    victim->operator_instance[0] = 2;
    assert(!reclaim_victim(root, WN_BLE));
    victim->operator_instance[0] = 1;
    assert(reclaim_victim(root, WN_BLE) == victim);
    root->operator_peer = victim->operator_peer = NULL;
    /* A later incarnation at the same slot with a different peer is no victim.
     * With every owner now a sole route, unconnected probes defer unchanged. */
    victim->attachment++;
    strcpy(victim->authenticated_peer, peer_c);
    assert(!reclaim_victim(root, WN_BLE));
    assert(additional_candidate(root, clock_us / 1000, true) == -1);
    assert(plan_additional_candidate(root, clock_us / 1000, true) == -1 && !retired);
    strcpy(victim->authenticated_peer, peer_a);
    assert(reclaim_victim(root, WN_BLE) == victim);
    assert(!retired);
    assert_no_allocations();
}

static void resource_accounting(void) {
    struct fixture f;
    struct peer_state *root = reset(&f);
    own(&f, 0, peer_a, WN_LAN, 128, true);
    own(&f, 1, peer_a, WN_BLE, 8192, false);
    own(&f, 2, peer_b, WN_BLE, 8192, true);
    own(&f, 3, peer_c, WN_BLE, 8192, true);
    assert(!medium_available(root, WN_BLE));
    assert(medium_available(root, WN_LAN));
    assert(reclaim_victim(root, WN_BLE) == &f.links[1]);
    /* A LAN-only redundant owner cannot satisfy the separate BLE ceiling. */
    f.links[1].candidate.medium = WN_LAN;
    physical.external = 1;
    assert(!medium_available(root, WN_BLE));
    assert(!reclaim_victim(root, WN_BLE));
    struct carrier_occupancy used;
    assert(carrier_occupancy(root, &used) && used.total == 5 && used.ble == 3);
    /* Released actor ownership stays charged through physical ownerRelease. */
    f.links[1].active = false;
    f.links[1].candidate_held = false;
    f.links[1].connection = NULL;
    physical.external = 2;
    physical.retiring = 1;
    assert(carrier_occupancy(root, &used) && used.total == 5 && used.retiring);
    assert(!medium_available(root, WN_BLE) && !reclaim_victim(root, WN_BLE));
    assert_no_allocations();
    /* A known empty provider which is not ready cannot block configured LAN.
     * It also cannot justify dropping LAN to manufacture a BLE radio slot. */
    root = reset(&f);
    own(&f, 0, peer_a, WN_LAN, 128, true);
    own(&f, 1, peer_a, WN_LAN, 512, false);
    physical.physical_ready = false;
    assert(candidate_room(root, WN_LAN));
    assert(!candidate_room(root, WN_BLE));
    assert(!reclaim_victim(root, WN_BLE));
    snapshot_ok = false;
    assert(!candidate_room(root, WN_LAN));
    assert_no_allocations();
}

static void planner_release_and_gates(void) {
    struct fixture f;
    full_redundant(&f);
    struct peer_state *root = &f.links[0];
    int probe = hint(&f, 0, NULL, WN_BLE, 8192);
    root->clock_ready = false;
    assert(plan_additional_candidate(root, clock_us / 1000, true) == -1 && !retired);
    root->clock_ready = true;
    free_heap = CONFIG_WENDY_NET_SETUP_FREE_BYTES - 1;
    assert(plan_additional_candidate(root, clock_us / 1000, true) == -1 && !retired);
    free_heap = CONFIG_WENDY_NET_SETUP_FREE_BYTES;
    mesh_limit = 0;
    assert(plan_additional_candidate(root, clock_us / 1000, true) == -1 && !retired);
    mesh_limit = 1;
    delay_release = true;
    uint64_t attachment = f.links[1].attachment;
    assert(plan_additional_candidate(root, clock_us / 1000, true) == -1);
    assert(retired == 1 && last_retired == &f.links[1]);
    assert(f.links[1].attachment == attachment + 1 && atomic_load(&root->active));
    assert(f.selection.candidates[probe].retry_ms == 0); /* No dial was attempted. */
    struct carrier_occupancy used;
    assert(carrier_occupancy(root, &used) && used.total == 8 && used.retiring);
    for (unsigned i = 0; i < 3; i++) {
        clock_us += 6000000;
        f.selection.candidates[probe].seen_ms = clock_us / 1000;
        assert(plan_additional_candidate(root, clock_us / 1000, true) == -1);
        assert(retired == 1);
    }
    physical = (struct wble_mesh_capacity){.physical_ready = true, .physical_free = 3};
    f.selection.candidates[probe].seen_ms = clock_us / 1000;
    assert(plan_additional_candidate(root, clock_us / 1000, true) == probe);
    assert(retired == 1);
    assert_no_allocations();

    /* A native dial/pending pipe already owns the next opportunity even before
     * it is retiring. Changing the selected candidate cannot reclaim a second
     * standby while that first join is awaiting the actor pickup. */
    full_redundant(&f); root = &f.links[0];
    f.links[7].active = false;
    f.links[7].candidate_held = false;
    f.links[7].connection = NULL;
    physical = (struct wble_mesh_capacity){.external = 1, .retiring = 0, .physical_free = 1,
                                         .physical_ready = true};
    probe = hint(&f, 0, NULL, WN_BLE, 8192);
    f.selection.candidates[probe].passive = true;
    int changed = hint(&f, 1, peer_b, WN_LAN, 128);
    assert(candidate_class(root, &f.selection.candidates[changed]) == 0);
    assert(carrier_occupancy(root, &used) && used.total == 8 && used.retiring);
    assert(plan_additional_candidate(root, clock_us / 1000, true) == -1 && !retired);
    assert(!f.links[1].failed && !f.links[1].tls_state.cancel);
    assert_no_allocations();

    /* Time bootstrap blocks the outgoing BLE dial before any destructive
     * capacity decision. A feasible LAN newcomer still participates normally. */
    full_redundant(&f); root = &f.links[0];
    root->bootstrap_time = root;
    probe = hint(&f, 0, NULL, WN_BLE, 8192);
    assert(additional_candidate(root, clock_us / 1000, true) == -1);
    assert(plan_additional_candidate(root, clock_us / 1000, true) == -1 && !retired);
    changed = hint(&f, 1, peer_b, WN_LAN, 128);
    assert(additional_candidate(root, clock_us / 1000, true) == changed);
    assert(plan_additional_candidate(root, clock_us / 1000, true) == changed);
    assert(retired == 1 && last_retired == &f.links[1]);
    assert(f.selection.candidates[probe].retry_ms == 0);
    assert(atomic_load(&root->active));
    assert_no_allocations();
}

static void incoming_probe(void) {
    struct fixture f;
    full_redundant(&f);
    struct peer_state *root = &f.links[0];
    /* Two redundant standbys make repeated receipts a meaningful one-inflight
     * check. There is no discovery row: this peer was first seen by CoC. */
    strcpy(f.links[2].authenticated_peer, peer_b);
    strcpy(f.links[2].candidate.device, peer_b);
    strcpy(f.links[3].authenticated_peer, peer_b);
    strcpy(f.links[3].candidate.device, peer_b);
    f.links[3].candidate.medium = WN_BLE;
    f.links[3].candidate.cost = 8192;
    f.routes[3].forwarding_until = 0;
    assert(wn_candidate_order(&f.selection, clock_us / 1000, 42, (unsigned[WN_CANDIDATES]){0}) == 0);
    assert(!ble_admission_available(root) && ble_probe_available(root));
    update_ble(root, peer_a, peer_a);
    assert(root->ble_published && (published_capabilities & WN_BLE_NATIVE_ACCEPTING));
    assert(!reclaim_for_incoming_probe(root) && !retired);
    capacity_refused = true;
    delay_release = true;
    assert(reclaim_for_incoming_probe(root));
    assert(retired == 1 && last_retired == &f.links[1] && !capacity_refused);
    assert(atomic_load(&root->active) && atomic_load(&f.links[3].active));
    assert(!ble_admission_available(root));
    assert(!ble_probe_available(root));
    update_ble(root, peer_a, peer_a);
    assert(!(published_capabilities & WN_BLE_NATIVE_ACCEPTING));
    for (unsigned i = 0; i < 3; i++) {
        clock_us += 1000000;
        capacity_refused = true;
        assert(!reclaim_for_incoming_probe(root) && retired == 1);
    }
    physical = (struct wble_mesh_capacity){.physical_ready = true, .physical_free = 2};
    assert(ble_admission_available(root)); /* Ordinary remote retry now fits. */
    assert(ble_probe_available(root));
    update_ble(root, peer_a, peer_a);
    assert(published_capabilities & WN_BLE_NATIVE_ACCEPTING);
    assert(!reclaim_for_incoming_probe(root) && retired == 1);
    assert_no_allocations();

    full_redundant(&f); root = &f.links[0];
    f.links[7].active = false;
    f.links[7].candidate_held = false;
    f.links[7].connection = NULL;
    physical = (struct wble_mesh_capacity){.external = 1, .retiring = 0, .physical_free = 1,
                                         .physical_ready = true};
    capacity_refused = true;
    assert(!reclaim_for_incoming_probe(root) && !retired);
    assert(!ble_admission_available(root) && !ble_probe_available(root));

    full_redundant(&f); root = &f.links[0];
    f.routes[1].selected_routes = true;
    assert(!ble_admission_available(root) && !ble_probe_available(root));
    capacity_refused = true;
    assert(!reclaim_for_incoming_probe(root) && !retired);
    f.routes[1].selected_routes = false;
    f.connections[1].borrowed = true;
    capacity_refused = true;
    assert(!reclaim_for_incoming_probe(root) && !retired);
    f.connections[1].borrowed = false;
    f.routes[0].forwarding_until = clock_us;
    capacity_refused = true;
    assert(!reclaim_for_incoming_probe(root) && !retired);
    assert(!f.links[1].failed && !f.links[1].tls_state.cancel);
    f.routes[0].forwarding_until = clock_us + 100000000;
    strcpy(f.links[1].authenticated_peer, peer_c);
    assert(!ble_admission_available(root) && !ble_probe_available(root));
    capacity_refused = true;
    assert(!reclaim_for_incoming_probe(root) && !retired);
    strcpy(f.links[1].authenticated_peer, peer_a);
    root->clock_ready = false;
    capacity_refused = true;
    assert(!reclaim_for_incoming_probe(root) && !retired);
    root->clock_ready = true;
    root->config.ble = false;
    capacity_refused = true;
    assert(!reclaim_for_incoming_probe(root) && !retired);
    root->config.ble = true;
    free_heap = CONFIG_WENDY_NET_SETUP_FREE_BYTES - 1;
    capacity_refused = true;
    assert(!reclaim_for_incoming_probe(root) && !retired);
    free_heap = CONFIG_WENDY_NET_SETUP_FREE_BYTES;
    mesh_limit = 0;
    capacity_refused = true;
    assert(!reclaim_for_incoming_probe(root) && !retired);
    assert(!f.links[1].failed && !f.links[1].tls_state.cancel);
    assert_no_allocations();
}

static int delayed_leaf_start(struct fixture *f, struct wble_mesh_peer *old_radio) {
    full_redundant(f);
    struct peer_state *root = &f->links[0], *old = &f->links[1];
    *old_radio = (struct wble_mesh_peer){.address = {1}, .psm = 129, .server = true};
    struct wn_candidate known = old->candidate;
    known.ble_capabilities = WN_BLE_NATIVE_ACCEPTING;
    ble_address(known.address, old_radio->address, old_radio->address_type);
    int index = wn_candidate_seen(&f->selection, &known, clock_us / 1000);
    assert(index >= 0 && !wn_candidate_hold(&f->selection, (unsigned)index));
    assert(!f->selection.candidates[index].authenticated);
    assert(!wn_candidate_authenticated(&f->selection, (unsigned)index, peer_a));
    assert(f->selection.candidates[index].authenticated);
    old->candidate = known;
    old->candidate_index = index;
    refused_peer = (struct wble_mesh_peer){.address = {2}, .psm = 129, .server = true};
    capacity_refused = true;
    delay_release = true;
    assert(reclaim_for_incoming_probe(root));
    assert(root->incoming_probe_waiting && !root->incoming_probe_until_us);
    assert(retired == 1 && !f->selection.candidates[index].holds);
    assert(f->selection.candidates[index].retry_ms == clock_us / 1000 + 5000);
    return index;
}

static void release_at(struct peer_state *root, int64_t at) {
    clock_us = at;
    physical = (struct wble_mesh_capacity){.physical_ready = true, .physical_free = 3};
    maintain_incoming_demand(root, clock_us);
    assert(!root->incoming_probe_waiting);
    assert(root->incoming_probe_until_us == at + INT64_C(1000) * WN_CANDIDATE_FAILURE_PENALTY_MS);
}

static void start_authenticated_setup(struct fixture *f, unsigned slot,
                                       const struct wn_candidate *candidate,
                                       const char *authenticated, bool incoming) {
    struct peer_state *link = &f->links[slot];
    link->setup_server = incoming;
    link->setup_have_stream = true;
    if (candidate->medium == WN_BLE) {
        assert(physical.physical_free);
        physical.physical_free--;
    }
    begin_setup(link, candidate, -1);
    assert(link->tls_channel && link->setup_waiting);
    link->connection = &f->connections[slot];
    link->identity_until = clock_us + 100000000;
    strcpy(link->authenticated_peer, authenticated);
    strcpy(link->identity.device, "00000000-0000-4000-8000-000000000000");
}

static void free_setup_channel(struct peer_state *link) {
    wendy_net_free(link->tls_channel);
    link->tls_channel = NULL;
}

static void incoming_retry_fairness(void) {
    struct fixture f;
    struct wble_mesh_peer old_radio;
    int old_index = delayed_leaf_start(&f, &old_radio);
    struct peer_state *root = &f.links[0];
    int64_t rejected_at = clock_us;
    /* The old standby's existing five-second floor elapses while physical
     * release is still outstanding. No speculative retry window starts yet. */
    clock_us += 5000000;
    f.selection.candidates[old_index].seen_ms = clock_us / 1000;
    maintain_incoming_demand(root, clock_us);
    assert(root->incoming_probe_waiting && !root->incoming_probe_until_us);
    assert(wn_candidate_order(&f.selection, clock_us / 1000, 42,
                              (unsigned[WN_CANDIDATES]){0}) == 1);
    assert(additional_candidate(root, clock_us / 1000, true) == -1 && retired == 1);
    /* Physical release alone is insufficient while the old actor's clock
     * completion still owns its slot. Start only after both owners release. */
    clock_us = 20000000;
    physical = (struct wble_mesh_capacity){.physical_ready = true, .physical_free = 3};
    f.links[1].clock.phase = CLOCK_RUNNING;
    maintain_incoming_demand(root, clock_us);
    assert(root->incoming_probe_waiting && !root->incoming_probe_until_us);
    f.links[1].clock.phase = CLOCK_EMPTY;
    release_at(root, 22000000);
    int64_t until = root->incoming_probe_until_us;
    assert(until > rejected_at + INT64_C(1000) * WN_CANDIDATE_FAILURE_PENALTY_MS);
    clock_us = 24000000;
    refused_peer = old_radio;
    capacity_refused = true;
    assert(!reclaim_for_incoming_probe(root));
    assert(root->incoming_probe_until_us == until && !root->incoming_probe_waiting);
    assert(incoming_standby_hint(root, &f.selection.candidates[old_index]));
    assert(pickup_defers_standby(root, old_radio));
    assert(gate_releases == 1 && !opens && !f.links[1].tls_channel);
    /* The unknown leaf retries on the existing 30s failure penalty. The old
     * five-second standby is due, but remains deferred through that retry. */
    clock_us = rejected_at + INT64_C(1000) * WN_CANDIDATE_FAILURE_PENALTY_MS;
    f.selection.candidates[old_index].seen_ms = clock_us / 1000;
    assert(additional_candidate(root, clock_us / 1000, true) == -1);
    struct wble_mesh_peer leaf = {.address = {2}, .psm = 129, .server = true};
    assert(!pickup_defers_standby(root, leaf));
    struct wn_candidate unknown = {.medium = WN_BLE, .port = 129, .cost = 8192};
    ble_address(unknown.address, leaf.address, leaf.address_type);
    start_authenticated_setup(&f, 1, &unknown, peer_b, true);
    assert(f.links[1].setup_incoming_demand);
    assert(admit_link(root, &f.links[1]) == 0);
    assert(!root->incoming_probe_waiting && !root->incoming_probe_until_us);
    assert(atomic_load(&root->active) && atomic_load(&f.links[1].active));
    free_setup_channel(&f.links[1]);
    assert_no_allocations();

    /* With no leaf returning, expiry is exactly 30s after real release. The
     * former standby then follows its existing discovery and TLS path. */
    old_index = delayed_leaf_start(&f, &old_radio); root = &f.links[0];
    release_at(root, 20000000);
    until = root->incoming_probe_until_us;
    clock_us = until - 1;
    f.selection.candidates[old_index].seen_ms = clock_us / 1000;
    maintain_incoming_demand(root, clock_us);
    assert(additional_candidate(root, clock_us / 1000, true) == -1);
    clock_us = until;
    maintain_incoming_demand(root, clock_us);
    assert(!incoming_demand_active(root, clock_us));
    assert(plan_additional_candidate(root, clock_us / 1000, true) == old_index);
    struct wn_candidate restore = f.selection.candidates[old_index];
    start_authenticated_setup(&f, 1, &restore, peer_a, false);
    assert(!f.links[1].setup_incoming_demand);
    assert(admit_link(root, &f.links[1]) == 0 && retired == 1);
    free_setup_channel(&f.links[1]);
    assert_no_allocations();

    /* A slow TLS setup captures the hold for either incoming or unknown
     * outgoing work. Authentication after expiry cannot revive an old peer's
     * cross-medium standby during the reserved new-peer attempt. */
    for (unsigned incoming = 0; incoming < 2; incoming++) {
        delayed_leaf_start(&f, &old_radio); root = &f.links[0];
        release_at(root, 20000000);
        until = root->incoming_probe_until_us;
        clock_us = 22000000;
        unknown = (struct wn_candidate){.medium = WN_BLE, .port = 129, .cost = 8192};
        struct wble_mesh_peer unrecognized = {.address = {3}, .psm = 129};
        ble_address(unknown.address, unrecognized.address, unrecognized.address_type);
        start_authenticated_setup(&f, 1, &unknown, peer_a, incoming != 0);
        assert(f.links[1].setup_incoming_demand);
        clock_us = until + 1;
        maintain_incoming_demand(root, clock_us);
        assert(!incoming_demand_active(root, clock_us));
        assert(admit_link(root, &f.links[1]) == -1 && !opens);
        assert(atomic_load(&root->active) && !atomic_load(&f.links[1].active));
        free_setup_channel(&f.links[1]);
        assert_no_allocations();
    }

    /* A pending owner with no actual release in progress gets a finite
     * refresh; it cannot make the original waiting anchor unbounded. */
    delayed_leaf_start(&f, &old_radio); root = &f.links[0];
    release_at(root, 20000000);
    clock_us = 25000000;
    physical = (struct wble_mesh_capacity){.external = 1, .physical_ready = true, .physical_free = 2};
    refused_peer = (struct wble_mesh_peer){.address = {4}, .psm = 129};
    capacity_refused = true;
    assert(!reclaim_for_incoming_probe(root) && retired == 1);
    assert(!root->incoming_probe_waiting && root->incoming_probe_until_us == 55000000);
    clock_us = 54000000;
    maintain_incoming_demand(root, clock_us);
    assert(!root->incoming_probe_waiting && incoming_demand_active(root, clock_us));
    clock_us = 55000000;
    maintain_incoming_demand(root, clock_us);
    assert(!incoming_demand_active(root, clock_us));
    /* Actual physical release does re-anchor the next held opportunity. */
    delayed_leaf_start(&f, &old_radio); root = &f.links[0];
    release_at(root, 20000000);
    clock_us = 25000000;
    physical = (struct wble_mesh_capacity){.external = 1, .retiring = 1,
                                         .physical_ready = true, .physical_free = 2};
    refused_peer = (struct wble_mesh_peer){.address = {4}, .psm = 129};
    capacity_refused = true;
    assert(!reclaim_for_incoming_probe(root) && retired == 1);
    assert(root->incoming_probe_waiting && !root->incoming_probe_until_us);
    clock_us = 55000000;
    maintain_incoming_demand(root, clock_us);
    assert(root->incoming_probe_waiting && !root->incoming_probe_until_us);
    release_at(root, 60000000);
    until = root->incoming_probe_until_us;
    clock_us = 61000000;
    refused_peer = old_radio;
    capacity_refused = true;
    assert(!reclaim_for_incoming_probe(root) && retired == 1);
    assert(root->incoming_probe_until_us == until);
    clock_us = 62000000;
    refused_peer = (struct wble_mesh_peer){.address = {4}, .psm = 129};
    capacity_refused = true;
    assert(!reclaim_for_incoming_probe(root) && retired == 1);
    assert(root->incoming_probe_until_us == clock_us +
           INT64_C(1000) * WN_CANDIDATE_FAILURE_PENALTY_MS);
    assert_no_allocations();
}

static void any_selected_survivor(void) {
    struct fixture f;
    full_redundant(&f);
    struct peer_state *root = &f.links[0], *selected_ble = &f.links[1];
    /* Cost does not authorize retirement. A cheap LAN owner with no selected
     * FIB routes is redundant even when its selected survivor is costlier BLE. */
    f.routes[0].forwarding_until = 0;
    f.routes[1].forwarding_until = clock_us + 100000000;
    f.routes[1].selected_routes = true;
    assert(root->candidate.cost < selected_ble->candidate.cost);
    assert(reclaim_victim(root, WN_LAN) == root);
    f.routes[0].selected_routes = true;
    assert(!reclaim_victim(root, WN_LAN));
    f.routes[0].selected_routes = false;
    selected_ble->candidate.cost = root->candidate.cost;
    assert(reclaim_victim(root, WN_LAN) == root); /* Equal-cost other medium. */
    selected_ble->candidate.cost = 8192;
    int newcomer = hint(&f, 0, peer_b, WN_LAN, 128);
    assert(plan_additional_candidate(root, clock_us / 1000, true) == newcomer);
    assert(retired == 1 && last_retired == root);
    assert(atomic_load(&selected_ble->active));
    assert(wnrs_peer_forwarding_ready(selected_ble->router, clock_us));
    assert_no_allocations();
}

static void tls_learned_endpoint_hint(void) {
    struct fixture f;
    struct wble_mesh_peer old_radio;
    int old_index = delayed_leaf_start(&f, &old_radio);
    struct peer_state *root = &f.links[0];
    release_at(root, 20000000);
    int64_t old_until = root->incoming_probe_until_us;
    struct wble_mesh_peer untrusted_radio = {.address = {9}, .psm = 129};
    struct wn_candidate copied = f.selection.candidates[old_index];
    assert(copied.authenticated);
    ble_address(copied.address, untrusted_radio.address, untrusted_radio.address_type);
    int index = wn_candidate_seen(&f.selection, &copied, clock_us / 1000);
    assert(index >= 0 && !f.selection.candidates[index].authenticated);
    /* Copying a UUID and even a provenance bit through discovery never makes
     * that on-air endpoint a TLS-learned standby or suppresses its probe. */
    assert(!incoming_standby_hint(root, &f.selection.candidates[index]));
    assert(!pickup_defers_standby(root, untrusted_radio));
    clock_us += 1000000;
    refused_peer = untrusted_radio;
    capacity_refused = true;
    assert(!reclaim_for_incoming_probe(root) && retired == 1);
    assert(root->incoming_probe_until_us > old_until);
    assert(root->incoming_probe_until_us == clock_us +
           INT64_C(1000) * WN_CANDIDATE_FAILURE_PENALTY_MS);
    /* Ordinary discovery that changes the endpoint's expected device clears
     * prior provenance. Only the real authenticated function can restore it. */
    struct wn_candidate changed = f.selection.candidates[old_index];
    strcpy(changed.device, peer_b);
    assert(wn_candidate_seen(&f.selection, &changed, clock_us / 1000) == old_index);
    assert(!f.selection.candidates[old_index].authenticated);
    assert(!wn_candidate_authenticated(&f.selection, (unsigned)old_index, peer_b));
    assert(f.selection.candidates[old_index].authenticated);
    assert_no_allocations();
}

static void discard_setup(struct peer_state *link) {
    free_setup_channel(link);
    if (link->candidate_held && link->candidate_index >= 0)
        wn_candidate_release(link->selection, (unsigned)link->candidate_index);
    link->candidate_held = false;
    link->setup_waiting = false;
    link->connection = NULL;
    link->router = NULL;
}

static void reserve_last_opportunity(void) {
    struct fixture f;
    for (unsigned cost_index = 0; cost_index < 2; cost_index++) {
        struct peer_state *root = reset(&f);
        root->config.max_links = 2;
        own(&f, 0, peer_a, WN_BLE, 8192, true);
        root->incoming_probe_until_us = clock_us + INT64_C(1000) * WN_CANDIDATE_FAILURE_PENALTY_MS;
        unsigned cost = cost_index ? 8192 : 128;
        int old_lan = hint(&f, 0, peer_a, WN_LAN, cost);
        assert(candidate_class(root, &f.selection.candidates[old_lan]) == (cost_index ? 2 : 1));
        assert(peer_has_working_carrier(root, NULL, peer_a));
        assert(incoming_opportunity_reserved(root, WN_LAN, false, false));
        assert(additional_candidate(root, clock_us / 1000, true) == -1);
        struct wn_candidate existing = f.selection.candidates[old_lan];
        start_authenticated_setup(&f, 1, &existing, peer_a, true);
        assert(admit_link(root, &f.links[1]) == -1 && !opens);
        assert(atomic_load(&root->active));
        discard_setup(&f.links[1]);
        /* After ordinary expiry, a cheap or equal upgrade can use the slot. */
        clock_us = root->incoming_probe_until_us;
        maintain_incoming_demand(root, clock_us);
        f.selection.candidates[old_lan].seen_ms = clock_us / 1000;
        assert(plan_additional_candidate(root, clock_us / 1000, true) == old_lan);
        start_authenticated_setup(&f, 1, &existing, peer_a, true);
        assert(!f.links[1].setup_incoming_demand);
        assert(admit_link(root, &f.links[1]) == 0 && opens == 1);
        free_setup_channel(&f.links[1]);
        assert_no_allocations();
    }

    /* A hold reserves one opportunity, not every spare unit. These known
     * cross-medium upgrades leave another total, medium and physical slot. */
    struct peer_state *root = reset(&f);
    own(&f, 0, peer_a, WN_BLE, 8192, true);
    root->incoming_probe_until_us = clock_us + INT64_C(1000) * WN_CANDIDATE_FAILURE_PENALTY_MS;
    int64_t until = root->incoming_probe_until_us;
    int upgrade = hint(&f, 0, peer_a, WN_LAN, 128);
    assert(!incoming_opportunity_reserved(root, WN_LAN, false, false));
    assert(plan_additional_candidate(root, clock_us / 1000, true) == upgrade);
    struct wn_candidate c = f.selection.candidates[upgrade];
    start_authenticated_setup(&f, 1, &c, peer_a, false);
    assert(admit_link(root, &f.links[1]) == 0);
    assert(root->incoming_probe_until_us == until);
    free_setup_channel(&f.links[1]);
    assert_no_allocations();

    root = reset(&f);
    own(&f, 0, peer_a, WN_LAN, 128, true);
    root->incoming_probe_until_us = clock_us + INT64_C(1000) * WN_CANDIDATE_FAILURE_PENALTY_MS;
    until = root->incoming_probe_until_us;
    upgrade = hint(&f, 0, peer_a, WN_BLE, 8192);
    root->config.ble_links = 1;
    assert(incoming_opportunity_reserved(root, WN_BLE, false, false));
    assert(additional_candidate(root, clock_us / 1000, true) == -1);
    root->config.ble_links = 2;
    physical.physical_free = 2; /* One time-only pipe occupies the third unit. */
    assert(!incoming_opportunity_reserved(root, WN_BLE, false, false));
    assert(plan_additional_candidate(root, clock_us / 1000, true) == upgrade);
    c = f.selection.candidates[upgrade];
    start_authenticated_setup(&f, 1, &c, peer_a, true);
    assert(physical.physical_free == 1);
    assert(admit_link(root, &f.links[1]) == 0);
    assert(root->incoming_probe_until_us == until);
    free_setup_channel(&f.links[1]);
    assert_no_allocations();

    /* Signed-time pipes can make physical capacity the final opportunity even
     * when the actor's total and native BLE logical budgets have spare units. */
    root = reset(&f);
    own(&f, 0, peer_a, WN_LAN, 128, true);
    root->incoming_probe_until_us = clock_us + INT64_C(1000) * WN_CANDIDATE_FAILURE_PENALTY_MS;
    struct wble_mesh_peer old_radio = {.address = {1}, .psm = 129};
    c = (struct wn_candidate){.medium = WN_BLE, .port = 129, .cost = 8192,
                              .ble_capabilities = WN_BLE_NATIVE_ACCEPTING};
    strcpy(c.device, peer_a);
    ble_address(c.address, old_radio.address, old_radio.address_type);
    upgrade = wn_candidate_seen(&f.selection, &c, clock_us / 1000);
    assert(upgrade >= 0 && !wn_candidate_authenticated(&f.selection, (unsigned)upgrade, peer_a));
    physical.physical_free = 1;
    assert(incoming_opportunity_reserved(root, WN_BLE, false, false));
    assert(additional_candidate(root, clock_us / 1000, true) == -1);
    physical.physical_free = 0; /* Host take owns the final pipe before actor setup. */
    assert(pickup_defers_standby(root, old_radio) && !f.links[1].tls_channel);
    physical.physical_free = 1;
    start_authenticated_setup(&f, 1, &c, peer_a, true);
    assert(physical.physical_free == 0);
    assert(admit_link(root, &f.links[1]) == -1 && !opens);
    free_setup_channel(&f.links[1]);
    assert_no_allocations();

    root = reset(&f);
    own(&f, 0, peer_a, WN_LAN, 128, true);
    root->incoming_probe_until_us = clock_us + INT64_C(1000) * WN_CANDIDATE_FAILURE_PENALTY_MS;
    until = root->incoming_probe_until_us;
    mesh_limit = 0;
    root->config.max_links = 1;
    clock_us += 5000000;
    refused_peer = (struct wble_mesh_peer){.address = {6}, .psm = 129};
    capacity_refused = true;
    assert(!reclaim_for_incoming_probe(root) && !retired);
    assert(!root->incoming_probe_waiting && root->incoming_probe_until_us > until);
    assert(root->incoming_probe_until_us == clock_us +
           INT64_C(1000) * WN_CANDIDATE_FAILURE_PENALTY_MS);
    assert_no_allocations();
}

static void recover_during_release(void) {
    struct fixture f;
    struct wble_mesh_peer old_radio;
    int recovery = delayed_leaf_start(&f, &old_radio);
    struct peer_state *root = &f.links[0];
    /* An unrelated spare actor unit exists. The original slower BLE owner
     * remains physically closing, while its surviving LAN loses routing. */
    f.links[7].active = false;
    f.links[7].candidate_held = false;
    f.links[7].connection = NULL;
    atomic_fetch_sub(&root->carrier_count, 1);
    f.routes[0].forwarding_until = clock_us;
    physical.physical_ready = true;
    physical.physical_free = 2;
    clock_us += 5000000;
    f.selection.candidates[recovery].seen_ms = clock_us / 1000;
    assert(root->incoming_probe_waiting && !root->incoming_probe_until_us);
    assert(!peer_has_working_carrier(root, NULL, peer_a));
    assert(!incoming_standby_hint(root, &f.selection.candidates[recovery]));
    assert(!pickup_defers_standby(root, old_radio));
    assert(plan_additional_candidate(root, clock_us / 1000, true) == recovery);
    struct wn_candidate c = f.selection.candidates[recovery];
    start_authenticated_setup(&f, 7, &c, peer_a, false);
    assert(f.links[7].setup_incoming_demand);
    assert(admit_link(root, &f.links[7]) == 0 && opens == 1);
    f.links[7].setup_waiting = false;
    assert(root->incoming_probe_waiting && !root->incoming_probe_until_us);
    opened_route.forwarding_until = clock_us + 100000000;
    opened_route.selected_routes = true;
    assert(peer_has_working_carrier(root, NULL, peer_a));
    maintain_incoming_demand(root, clock_us);
    assert(root->incoming_probe_waiting && !root->incoming_probe_until_us);
    /* Same-UUID recovery does not clear or spend the original release anchor. */
    clock_us = 20000000;
    physical = (struct wble_mesh_capacity){.physical_ready = true, .physical_free = 2};
    maintain_incoming_demand(root, clock_us);
    assert(!root->incoming_probe_waiting);
    assert(root->incoming_probe_until_us == clock_us +
           INT64_C(1000) * WN_CANDIDATE_FAILURE_PENALTY_MS);
    /* Once recovery is selected and no join/release remains in flight, fresh
     * unknown demand may reclaim the now-unused old LAN for its next attempt. */
    root->config.max_links = 7;
    clock_us += 1000000;
    refused_peer = (struct wble_mesh_peer){.address = {5}, .psm = 129};
    capacity_refused = true;
    assert(reclaim_for_incoming_probe(root));
    assert(retired == 2 && last_retired == root);
    assert(atomic_load(&f.links[7].active) && wnrs_peer_forwarding_ready(f.links[7].router, clock_us));
    assert(root->incoming_probe_waiting && !root->incoming_probe_until_us);
    maintain_incoming_demand(root, clock_us);
    assert(!root->incoming_probe_waiting && incoming_demand_active(root, clock_us));
    free_setup_channel(&f.links[7]);
    assert_no_allocations();
}

static void verified_tls_result(struct fixture *f, unsigned slot, const char *peer) {
    struct peer_state *link = &f->links[slot];
    verified_connection = &f->connections[slot];
    strcpy(verified_identity.device, "00000000-0000-4000-8000-000000000000");
    strcpy(verified_identity.tenant, "90000000-0000-4000-8000-000000000009");
    strcpy(verified_identity.peer, peer);
    verified_identity.config_generation = 7;
    memset(verified_identity.trust_hash, 0x11, sizeof verified_identity.trust_hash);
    memset(verified_identity.journal_trust_hash, 0x22, sizeof verified_identity.journal_trust_hash);
    verified_identity.verified_monotonic_us = clock_us;
    link->identity_until = clock_us + 100000000;
    assert(setup_authenticated_stage(link) == 0);
    assert(link->connection == verified_connection && link->hello_started);
    assert(!strcmp(link->authenticated_peer, peer));
}

static void recovery_history_before_authentication(void) {
    struct fixture f;
    struct peer_state *root = reset(&f), *recovering = &f.links[1];
    own(&f, 0, peer_a, WN_LAN, 128, true);
    root->incoming_probe_waiting = true;
    physical.external = physical.retiring = 1;
    physical.physical_free = 2;
    struct wn_candidate c = {.medium = WN_BLE, .port = 129, .cost = 8192,
                              .address = "cached-recovery", .ble_capabilities = WN_BLE_NATIVE_ACCEPTING};
    strcpy(c.device, peer_a);
    int cached = wn_candidate_seen(&f.selection, &c, clock_us / 1000);
    assert(cached >= 0 && !wn_candidate_authenticated(&f.selection, (unsigned)cached, peer_a));
    int other_history = hint(&f, 1, peer_a, WN_BLE, 8192);
    assert(!wn_candidate_authenticated(&f.selection, (unsigned)other_history, peer_a));
    recovering->setup_have_stream = true;
    begin_setup(recovering, &c, -1);
    assert(recovering->candidate.authenticated && !strcmp(recovering->authenticated_peer, peer_a));
    assert(recovering->setup_incoming_demand);
    /* The live incumbent can retire and other unheld cache history can churn
     * before TLS finishes. The setup's verified prior endpoint stays pinned. */
    retire_link(root);
    for (unsigned i = 10; i < 10 + 2 * WN_CANDIDATES; i++) {
        clock_us += 1000;
        hint(&f, i, NULL, WN_LAN, 128);
    }
    assert(!atomic_load(&root->active));
    assert(f.selection.candidates[cached].holds == 1);
    assert(!f.selection.candidates[other_history].authenticated ||
           strcmp(f.selection.candidates[other_history].device, peer_a));
    unsigned remaining_history = 0;
    for (unsigned i = 0; i < WN_CANDIDATES; i++)
        remaining_history += f.selection.candidates[i].authenticated &&
                             !strcmp(f.selection.candidates[i].device, peer_a);
    assert(remaining_history == 1);
    assert(recovering->candidate.authenticated);
    verified_tls_result(&f, 1, peer_a);
    assert(recovering->candidate.authenticated);
    assert(admit_link(root, recovering) == 0);
    assert(root->incoming_probe_waiting && !root->incoming_probe_until_us);
    free_setup_channel(recovering);
    assert_no_allocations();

    /* A new endpoint for an already TLS-known UUID pins that prior UUID at
     * begin_setup, even though the new endpoint's own row is not verified yet. */
    root = reset(&f); recovering = &f.links[1];
    own(&f, 0, peer_a, WN_LAN, 128, true);
    root->incoming_probe_waiting = true;
    physical.external = physical.retiring = 1;
    physical.physical_free = 2;
    int history = hint(&f, 1, peer_a, WN_BLE, 8192);
    assert(!wn_candidate_authenticated(&f.selection, (unsigned)history, peer_a));
    c = (struct wn_candidate){.medium = WN_BLE, .port = 129, .cost = 8192,
                              .address = "new-address-for-old-UUID", .ble_capabilities = WN_BLE_NATIVE_ACCEPTING};
    strcpy(c.device, peer_a);
    recovering->setup_have_stream = true;
    begin_setup(recovering, &c, -1);
    assert(recovering->candidate.authenticated && !strcmp(recovering->authenticated_peer, peer_a));
    assert(!f.selection.candidates[recovering->candidate_index].authenticated);
    retire_link(root);
    for (unsigned i = 30; i < 30 + 2 * WN_CANDIDATES; i++) {
        clock_us += 1000;
        hint(&f, i, NULL, WN_LAN, 128);
    }
    assert(!previously_authenticated_peer(root, peer_a));
    verified_tls_result(&f, 1, peer_a);
    assert(recovering->candidate.authenticated);
    assert(admit_link(root, recovering) == 0);
    assert(root->incoming_probe_waiting && !root->incoming_probe_until_us);
    free_setup_channel(recovering);
    assert_no_allocations();

    /* Its own newly verified cache row cannot turn a genuinely new UUID into
     * prior recovery context. Only admitting that new peer clears the hold. */
    root = reset(&f); recovering = &f.links[1];
    own(&f, 0, peer_a, WN_LAN, 128, true);
    root->incoming_probe_waiting = true;
    physical.external = physical.retiring = 1;
    physical.physical_free = 2;
    c = (struct wn_candidate){.medium = WN_BLE, .port = 129, .cost = 8192,
                              .address = "new-endpoint", .ble_capabilities = WN_BLE_NATIVE_ACCEPTING};
    recovering->setup_have_stream = true;
    begin_setup(recovering, &c, -1);
    assert(!recovering->candidate.authenticated && !recovering->authenticated_peer[0]);
    assert(!previously_authenticated_peer(root, peer_b));
    verified_tls_result(&f, 1, peer_b);
    assert(!recovering->candidate.authenticated);
    assert(f.selection.candidates[recovering->candidate_index].authenticated);
    assert(previously_authenticated_peer(root, peer_b));
    assert(root->incoming_probe_waiting);
    assert(admit_link(root, recovering) == 0);
    assert(!root->incoming_probe_waiting && !root->incoming_probe_until_us);
    free_setup_channel(recovering);
    assert_no_allocations();
}

static void recovery_at_full_budget(void) {
    struct fixture f;
    full_redundant(&f);
    struct peer_state *root = &f.links[0];
    strcpy(f.links[2].candidate.device, peer_b);
    strcpy(f.links[2].authenticated_peer, peer_b);
    f.routes[2].forwarding_until = 0;
    int recovery = hint(&f, 0, peer_b, WN_BLE, 8192);
    assert(candidate_class(root, &f.selection.candidates[recovery]) == 0);
    assert(!peer_has_working_carrier(root, NULL, peer_b));
    assert(additional_candidate(root, clock_us / 1000, true) == recovery);
    assert(plan_additional_candidate(root, clock_us / 1000, true) == recovery);
    assert(retired == 1 && last_retired == &f.links[1]);
    assert(atomic_load(&root->active) && wnrs_peer_forwarding_ready(root->router, clock_us));
    assert(atomic_load(&f.links[2].active));
    assert_no_allocations();
}

static void outgoing_probe_keeps_reclaimed_opportunity(void) {
    struct fixture f;
    full_redundant(&f);
    struct peer_state *root = &f.links[0];
    strcpy(f.links[2].candidate.device, peer_b);
    strcpy(f.links[2].authenticated_peer, peer_b);
    int probe = hint(&f, 0, NULL, WN_BLE, 8192);
    int standby = hint(&f, 1, peer_b, WN_BLE, 8192);
    assert(probe == 0 && standby == 1);
    struct wn_candidate victim_hint = f.links[1].candidate;
    int victim_row = wn_candidate_seen(&f.selection, &victim_hint, clock_us / 1000);
    assert(victim_row >= 0 && !wn_candidate_hold(&f.selection, (unsigned)victim_row));
    f.links[1].candidate_index = victim_row;
    assert(candidate_class(root, &f.selection.candidates[probe]) == 0);
    assert(candidate_class(root, &f.selection.candidates[standby]) == 2);
    assert(additional_candidate(root, clock_us / 1000, true) == probe);
    delay_release = true;
    int64_t reclaimed_at = clock_us;
    assert(plan_additional_candidate(root, clock_us / 1000, true) == -1);
    assert(retired == 1 && last_retired == &f.links[1]);
    assert(f.selection.candidates[probe].retry_ms == 0);
    assert(f.selection.candidates[standby].retry_ms == 0);
    assert(f.selection.candidates[victim_row].retry_ms == reclaimed_at / 1000 + 5000);
    /* At actual release one second later, both the unknown probe and another
     * peer's warm standby are eligible. No unattempted-dial cooldown can let
     * the standby steal the opportunity that caused this reclamation. */
    clock_us += 1000000;
    physical = (struct wble_mesh_capacity){.physical_ready = true, .physical_free = 3};
    assert(clock_us < reclaimed_at + 5000000);
    unsigned order[WN_CANDIDATES];
    assert(wn_candidate_order(&f.selection, clock_us / 1000, 42, order) == 2);
    assert((order[0] == (unsigned)probe && order[1] == (unsigned)standby) ||
           (order[1] == (unsigned)probe && order[0] == (unsigned)standby));
    assert(!candidate_used(root, &f.selection.candidates[standby]));
    assert(additional_candidate(root, clock_us / 1000, true) == probe);
    assert(plan_additional_candidate(root, clock_us / 1000, true) == probe);
    assert(retired == 1 && f.selection.candidates[probe].retry_ms == 0);
    assert(candidate_class(root, &f.selection.candidates[standby]) == 2);
    assert_no_allocations();
}

static void start_operator_setup(struct fixture *f, unsigned slot,
                                 const struct wn_candidate *candidate,
                                 const struct operator_peer *operator_peer, uint8_t instance) {
    struct peer_state *link = &f->links[slot];
    link->setup_have_stream = true;
    link->setup_server = true;
    if (candidate->medium == WN_BLE) {
        assert(physical.physical_free);
        physical.physical_free--;
    }
    begin_setup(link, candidate, -1);
    verified_operator = operator_peer;
    verified_tls_result(f, slot, "");
    /* The following ordinary operator hello supplies the authenticated
     * installation token. Its principal comes from the verified TLS result. */
    memset(link->operator_instance, instance, sizeof link->operator_instance);
    assert(link->operator_peer == operator_peer && !link->candidate_held);
}

static void operator_reconnect_keeps_bounded_receipt(void) {
    const struct operator_peer alice = {.principal = "tenant/operator/Alice"};
    const struct operator_peer bob = {.principal = "tenant/operator/Bob"};
    for (unsigned new_operator = 0; new_operator < 2; new_operator++) {
        struct fixture f;
        struct peer_state *root = reset(&f), *reconnect = &f.links[1];
        root->config.max_links = 2;
        own(&f, 0, peer_a, WN_LAN, 128, true);
        root->operator_peer = &alice;
        memset(root->operator_instance, 42, sizeof root->operator_instance);
        root->incoming_probe_waiting = true;
        physical.external = physical.retiring = 1;
        physical.physical_free = 2;
        struct wn_candidate c = {.medium = WN_BLE, .port = 129, .cost = 8192,
                                  .address = "operator-reconnect"};
        reconnect->setup_have_stream = true;
        reconnect->setup_server = true;
        physical.physical_free--;
        begin_setup(reconnect, &c, -1);
        assert(reconnect->setup_incoming_demand);
        /* The old principal/instance owner disappears before TLS completes. */
        retire_link(root);
        root->operator_peer = NULL; /* close_session retires this old role. */
        verified_operator = new_operator ? &bob : &alice;
        verified_tls_result(&f, 1, "");
        memset(reconnect->operator_instance, new_operator ? 99 : 42,
               sizeof reconnect->operator_instance);
        assert(!peer_has_working_carrier(root, reconnect, NULL));
        assert(admit_link(root, reconnect) == 0 && opens == 1 && operator_opens == 1);
        reconnect->setup_waiting = false;
        assert(root->incoming_probe_waiting && !root->incoming_probe_until_us);
        assert(!strcmp(reconnect->operator_peer->principal, new_operator ? bob.principal : alice.principal));
        assert(reconnect->operator_instance[0] == (new_operator ? 99 : 42));
        maintain_incoming_demand(root, clock_us);
        assert(root->incoming_probe_waiting);
        physical = (struct wble_mesh_capacity){.physical_ready = true, .physical_free = 2};
        clock_us = 20000000;
        maintain_incoming_demand(root, clock_us);
        assert(!root->incoming_probe_waiting);
        int64_t until = root->incoming_probe_until_us;
        assert(until == clock_us + INT64_C(1000) * WN_CANDIDATE_FAILURE_PENALTY_MS);
        opened_route.forwarding_until = clock_us + 100000000;
        opened_route.selected_routes = true;
        free_setup_channel(reconnect);
        c = (struct wn_candidate){.medium = WN_LAN, .port = 43024, .cost = 128,
                                  .address = "operator-upgrade"};
        start_operator_setup(&f, 2, &c, reconnect->operator_peer, reconnect->operator_instance[0]);
        assert(same_peer(reconnect, &f.links[2]));
        assert(admit_link(root, &f.links[2]) == -1 && opens == 1);
        discard_setup(&f.links[2]);
        clock_us = until;
        maintain_incoming_demand(root, clock_us);
        assert(!incoming_demand_active(root, clock_us));
        start_operator_setup(&f, 2, &c, reconnect->operator_peer, reconnect->operator_instance[0]);
        assert(!f.links[2].setup_incoming_demand);
        assert(admit_link(root, &f.links[2]) == 0 && opens == 2 && operator_opens == 2);
        free_setup_channel(&f.links[2]);
        assert_no_allocations();
    }
}

static void last_slot_recovery_starts_finite_deadline(void) {
    struct fixture f;
    struct peer_state *root = reset(&f);
    root->config.max_links = 2;
    own(&f, 0, peer_a, WN_LAN, 128, false);
    root->incoming_probe_waiting = true;
    physical = (struct wble_mesh_capacity){.external = 1, .retiring = 1,
                                         .physical_ready = true, .physical_free = 2};
    int known = hint(&f, 0, peer_a, WN_BLE, 8192);
    assert(!wn_candidate_authenticated(&f.selection, (unsigned)known, peer_a));
    struct wn_candidate recovery = f.selection.candidates[known];
    /* Losing the primary path frees the only actor unit not held by the
     * original victim's physical close. Real recovery fills that final unit. */
    retire_link(root);
    root->setup_have_stream = true;
    physical.physical_free--;
    begin_setup(root, &recovery, -1);
    assert(root->candidate.authenticated);
    verified_tls_result(&f, 0, peer_a);
    assert(admit_link(root, root) == 0);
    root->setup_waiting = false;
    assert(root->incoming_probe_waiting && !root->incoming_probe_until_us);
    assert(!candidate_room(root, WN_BLE));
    maintain_incoming_demand(root, clock_us);
    assert(root->incoming_probe_waiting);
    /* After actual original release, a newly accepted pending owner can keep
     * total capacity full. It is not a release and cannot pin waiting forever. */
    clock_us = 20000000;
    physical = (struct wble_mesh_capacity){.external = 1, .retiring = 0,
                                         .physical_ready = true, .physical_free = 1};
    struct carrier_occupancy used;
    assert(carrier_occupancy(root, &used) && used.total == root->config.max_links && !used.releasing);
    assert(!candidate_room(root, WN_BLE));
    maintain_incoming_demand(root, clock_us);
    assert(!root->incoming_probe_waiting);
    int64_t until = clock_us + INT64_C(1000) * WN_CANDIDATE_FAILURE_PENALTY_MS;
    assert(root->incoming_probe_until_us == until);
    clock_us = until;
    maintain_incoming_demand(root, clock_us);
    assert(!incoming_demand_active(root, clock_us));
    assert(!candidate_room(root, WN_BLE));
    free_setup_channel(root);
    assert_no_allocations();
}

static void prepare_pending_device_alias(struct fixture *f, unsigned slot,
                                          enum wn_medium medium, const char *address) {
    assert(setup_capacity_available(&f->links[0]));
    struct peer_state *link = &f->links[slot];
    struct wn_candidate c = {.medium = medium, .port = medium == WN_BLE ? 129 : 43024,
                              .cost = medium == WN_BLE ? 8192 : 128,
                              .ble_capabilities = WN_BLE_NATIVE_ACCEPTING};
    strcpy(c.address, address);
    link->setup_have_stream = true;
    link->setup_server = true;
    if (medium == WN_BLE) { assert(physical.physical_free); physical.physical_free--; }
    begin_setup(link, &c, -1);
    verified_tls_result(f, slot, peer_b);
    assert(link->setup_waiting);
}

static void bound_alias_preserves_refreshed_incoming_demand(void) {
    struct fixture f;
    struct peer_state *root = reset(&f), *first = &f.links[1], *later = &f.links[2];
    root->config.max_links = 3;
    mesh_limit = 2;
    own(&f, 0, peer_a, WN_LAN, 128, true);
    root->incoming_probe_until_us = clock_us + INT64_C(1000) * WN_CANDIDATE_FAILURE_PENALTY_MS;
    int64_t old_until = root->incoming_probe_until_us;
    prepare_pending_device_alias(&f, 1, WN_LAN, "first-alias-delayed");
    assert(!first->candidate.authenticated);
    prepare_pending_device_alias(&f, 2, WN_BLE, "later-alias-binds");
    assert(later->candidate.authenticated && !setup_capacity_available(root));
    assert(admit_link(root, later) == 0);
    later->setup_waiting = false;
    assert(root->incoming_probe_until_us == old_until);
    assert(first->candidate.authenticated); /* Successful binding promotes this verified alias. */
    delay_release = true;
    retire_link(later);
    clock_us += 1000000;
    capacity_refused = true;
    refused_peer = (struct wble_mesh_peer){0};
    assert(!reclaim_for_incoming_probe(root));
    assert(root->incoming_probe_waiting && !root->incoming_probe_until_us);
    assert(first->setup_waiting && !atomic_load(&later->active));
    /* The live-peer rescan now finds nobody, but the successful bind's
     * promotion prevents the delayed alias from clearing the newer refresh. */
    assert(!peer_has_working_carrier(root, first, NULL));
    assert(admit_link(root, first) == 0);
    first->setup_waiting = false;
    assert(root->incoming_probe_waiting && !root->incoming_probe_until_us);
    free_setup_channel(first);
    free_setup_channel(later);
    assert_no_allocations();
}

static void bound_alias_promotion_boundaries(void) {
    const struct operator_peer op = {.principal = "tenant/operator/Alice"};
    for (unsigned boundary = 0; boundary < 13; boundary++) {
        struct fixture f;
        struct peer_state *root = reset(&f), *pending = &f.links[1], *bound = &f.links[2];
        mesh_limit = 2;
        own(&f, 0, peer_a, WN_LAN, 128, true);
        root->incoming_probe_until_us = clock_us + INT64_C(1000) * WN_CANDIDATE_FAILURE_PENALTY_MS;
        prepare_pending_device_alias(&f, 1, WN_LAN, "pending-verified-alias");
        prepare_pending_device_alias(&f, 2, WN_BLE, "binding-verified-alias");
        assert(!pending->candidate.authenticated && bound->candidate.authenticated);
        switch (boundary) {
        case 0: strcpy(pending->authenticated_peer, peer_c); break;
        case 1: strcpy(pending->identity.peer, peer_c); break;
        case 2: strcpy(pending->identity.tenant, "80000000-0000-4000-8000-000000000008"); break;
        case 3: strcpy(pending->identity.device, peer_c); break;
        case 4: pending->identity.config_generation++; break;
        case 5: pending->identity.trust_hash[0] ^= 1; break;
        case 6: pending->identity.journal_trust_hash[0] ^= 1; break;
        case 7: pending->hello_started = false; break;
        case 8: pending->connection = NULL; break;
        case 9: pending->operator_peer = &op; break;
        case 10: pending->setup_waiting = false; break;
        case 11: bound->operator_peer = &op; break;
        case 12: open_succeeds = false; break;
        }
        if (boundary == 11) {
            promote_bound_device_aliases(root, bound);
        } else if (boundary == 12) {
            assert(admit_link(root, bound) == -1 && !atomic_load(&bound->active));
            assert(!opens);
        } else {
            assert(admit_link(root, bound) == 0);
        }
        assert(!pending->candidate.authenticated);
        assert(root->incoming_probe_until_us != 0);
        free_setup_channel(pending);
        free_setup_channel(bound);
        assert_no_allocations();
    }

    /* The fix does not classify an actual first new device as prior context:
     * its successful admission still satisfies and clears its current hold. */
    struct fixture f;
    struct peer_state *root = reset(&f);
    own(&f, 0, peer_a, WN_LAN, 128, true);
    mesh_limit = 2;
    root->incoming_probe_until_us = clock_us + INT64_C(1000) * WN_CANDIDATE_FAILURE_PENALTY_MS;
    prepare_pending_device_alias(&f, 1, WN_LAN, "genuinely-first-new-device");
    assert(!f.links[1].candidate.authenticated);
    assert(admit_link(root, &f.links[1]) == 0);
    assert(!root->incoming_probe_waiting && !root->incoming_probe_until_us);
    free_setup_channel(&f.links[1]);
    assert_no_allocations();

    /* An unverified same-UUID discovery expectation is not an authenticated
     * pending alias. A real first TLS bind neither promotes nor trusts it. */
    root = reset(&f);
    own(&f, 0, peer_a, WN_LAN, 128, true);
    mesh_limit = 2;
    root->incoming_probe_until_us = clock_us + INT64_C(1000) * WN_CANDIDATE_FAILURE_PENALTY_MS;
    struct wn_candidate hint_only = {.medium = WN_LAN, .port = 43024, .cost = 128,
                                     .address = "hint-only-same-UUID"};
    strcpy(hint_only.device, peer_b);
    f.links[1].setup_have_stream = true;
    begin_setup(&f.links[1], &hint_only, -1);
    assert(!f.links[1].hello_started && !f.links[1].connection && !f.links[1].authenticated_peer[0]);
    prepare_pending_device_alias(&f, 2, WN_BLE, "first-real-TLS-device");
    assert(!f.links[2].candidate.authenticated);
    assert(admit_link(root, &f.links[2]) == 0);
    assert(!f.links[1].candidate.authenticated);
    assert(!root->incoming_probe_waiting && !root->incoming_probe_until_us);
    free_setup_channel(&f.links[1]);
    free_setup_channel(&f.links[2]);
    assert_no_allocations();
}
#endif
int main(void) {
    assert(wendy_net_runtime_memory_open());
    /* Keep both profile builds strict about declarations and boundary stubs. */
    (void)heap_caps_get_free_size;
    (void)wendy_pki_handshake_mesh_limit;
    (void)wncrypto_borrowed;
    (void)wnrs_peer_forwarding_ready;
    (void)wnrs_reclaim_idle;
    (void)identity_live;
    (void)wble_mesh_capacity_snapshot;
    (void)wble_mesh_take_capacity_refusal;
    (void)wble_mesh_incoming_available;
    (void)retire_link;
    (void)wnrs_node_busy;
    (void)wnrs_link_id;
    (void)fixture_log;
    (void)TAG;
    (void)wnrs_open;
    (void)wnrs_open_operator;
    (void)reserve_candidate;
    (void)wble_mesh_profile;
    (void)wnad_connect;
    (void)wnad_prepare_socket;
    (void)close;
    (void)wble_mesh_release;
    (void)node_root;
    (void)wendy_pki_net_take;
    (void)wendy_pki_mesh_authenticated_operator;
    (void)wnad_handshake_release;
    (void)peer_b;
    (void)peer_c;
    (void)full_redundant;
    if (WENDY_NET_NON_TRANSIT) constrained();
#if !WENDY_NET_NON_TRANSIT
    else {
        priority_and_aliases();
        authenticated_admission();
        reclaim_boundaries();
        resource_accounting();
        planner_release_and_gates();
        incoming_probe();
        incoming_retry_fairness();
        any_selected_survivor();
        tls_learned_endpoint_hint();
        reserve_last_opportunity();
        recover_during_release();
        recovery_history_before_authentication();
        recovery_at_full_budget();
        outgoing_probe_keeps_reclaimed_opportunity();
        operator_reconnect_keeps_bounded_receipt();
        last_slot_recovery_starts_finite_deadline();
        bound_alias_preserves_refreshed_incoming_demand();
        bound_alias_promotion_boundaries();
    }
#endif
    assert_no_allocations();
    wendy_net_runtime_memory_close();
    assert(wendy_net_runtime_memory_drained());
    printf("production actor policy constrained=%d: PASS; policy allocations=0\n", WENDY_NET_NON_TRANSIT);
    return 0;
}
'''

ble_header = (root.parent / 'wendy_ble/include/wendy_ble_mesh.h').read_text()
common_names = ('node_root', 'ble_address', 'clock_idle', 'slot_free', 'capacity_available', 'medium_available',
                'same_peer', 'candidate_used', 'additional_candidate')
with tempfile.TemporaryDirectory() as tmp:
    p = Path(tmp)
    for constrained_profile in (0, 1):
        prefix = head + structure(ble_header, 'wble_mesh_capacity') + structure(ble_header, 'wble_mesh_peer') + effects
        if not constrained_profile:
            prefix += structure(source, 'carrier_occupancy')
        names = list(common_names)
        if constrained_profile:
            names.insert(names.index('candidate_used'), 'cheaper_ip_carrier')
            names.extend(('setup_room', 'setup_capacity_available', 'ble_admission_available', 'update_ble'))
        else:
            # Definitions retain their real call graph instead of a copied policy.
            names = ['node_root', 'release_candidate', 'previously_authenticated_peer',
                     'ble_address', 'clock_idle', 'slot_free', 'incoming_demand_active',
                     'carrier_occupancy', 'capacity_available',
                     'medium_available', 'same_peer', 'peer_has_working_carrier',
                     'incoming_opportunity_reserved', 'promote_bound_device_aliases',
                     'commit_carrier', 'admit_link',
                     'candidate_used', 'candidate_class',
                     'reclaimable_carrier', 'reclaim_victim', 'candidate_room', 'ble_discovery_available',
                     'additional_candidate', 'setup_room', 'setup_capacity_available',
                     'plan_additional_candidate', 'incoming_standby_hint', 'maintain_incoming_demand',
                     'reclaim_for_incoming_probe', 'ble_admission_available', 'ble_probe_available',
                     'begin_setup', 'update_ble']
        prefix += structure(source, 'ble_seen')
        gate = '' if constrained_profile else incoming_pickup_gate() + setup_authentication_stage()
        (p / 'test.c').write_text(prefix + ''.join(definition(name) for name in names) + gate + main)
        subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', '-pthread',
                        '-DCONFIG_WENDY_NET_BLE=1',
                        '-DCONFIG_WENDY_NET_BLE_PSM=129',
                        '-DCONFIG_WENDY_NET_KEEP_REDUNDANT_BLE=0',
                        '-DCONFIG_WENDY_NET_SETUP_FREE_BYTES=1024',
                        '-DCONFIG_WENDY_NET_RETAIN_TLS_INPUT=0',
                        '-DWENDY_NET_MEMORY_HOST_BUDGET_TEST=1',
                        '-DCONFIG_WENDY_NET_CONSTRAINED_PROFILE=' + str(constrained_profile),
                        '-I' + str(root / 'include'),
                        '-I' + str(root.parent / 'wendy_net_common/include'),
                        str(p / 'test.c'), str(root / 'src/selection.c'),
                        str(root.parent / 'wendy_net_common/src/memory.c'),
                        str(root.parent / 'wendy_net_common/src/runtime_memory.c'),
                        '-o', str(p / 'test')], check=True)
        subprocess.run([str(p / 'test')], check=True)
