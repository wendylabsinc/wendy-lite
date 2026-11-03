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
    struct { char device[37]; int64_t verified_monotonic_us; } identity;
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
};
enum { CLOCK_EMPTY, CLOCK_RUNNING };
#define REFRESH_INTERVAL_US 1000000
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
static unsigned opens;
static int wnrs_open(struct wnrs **out, void *owner, struct connection *connection,
                     const void *identity, const void *peer, unsigned cost,
                     int (*send)(void *, const void *, size_t, bool), void *context) {
    (void)owner; (void)identity; (void)peer; (void)cost;
    assert(connection && send == router_send && context);
    *out = &opened_route; opens++; return 0;
}
static int wnrs_open_operator(struct wnrs **out, void *owner, struct connection *connection,
                              const void *identity, const void *peer, unsigned cost,
                              int (*send)(void *, const void *, size_t, bool), void *context) {
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
    }
}
static unsigned wble_mesh_profile(void) { return 0; }
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
    snapshots = retired = opens = refusal_reads = 0;
    capacity_refused = false;
    refused_peer = (struct wble_mesh_peer){0};
    gate_releases = 0;
    advertisement_publishes = 0;
    written_capabilities = published_capabilities = 0;
    last_retired = NULL;
    snapshot_ok = true;
    delay_release = false;
    physical = (struct wble_mesh_capacity){.physical_ready = true};
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
    assert(f.selection.candidates[probe].retry_ms >= clock_us / 1000 + 5000);
    struct carrier_occupancy used;
    assert(carrier_occupancy(root, &used) && used.total == 8 && used.retiring);
    for (unsigned i = 0; i < 3; i++) {
        clock_us += 6000000;
        f.selection.candidates[probe].seen_ms = clock_us / 1000;
        assert(plan_additional_candidate(root, clock_us / 1000, true) == -1);
        assert(retired == 1);
    }
    physical = (struct wble_mesh_capacity){.physical_ready = true};
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
    physical = (struct wble_mesh_capacity){.external = 1, .retiring = 0,
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
    physical = (struct wble_mesh_capacity){.physical_ready = true};
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
    physical = (struct wble_mesh_capacity){.external = 1, .retiring = 0,
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
    physical = (struct wble_mesh_capacity){.physical_ready = true};
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
    physical = (struct wble_mesh_capacity){.physical_ready = true};
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

    /* A fresh unknown refusal while an unrelated native owner is pending
     * re-awaits real room instead of spending the remaining hold while busy. */
    delayed_leaf_start(&f, &old_radio); root = &f.links[0];
    release_at(root, 20000000);
    clock_us = 25000000;
    physical = (struct wble_mesh_capacity){.external = 1, .physical_ready = true};
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
            names = ['node_root', 'ble_address', 'clock_idle', 'slot_free', 'incoming_demand_active',
                     'carrier_occupancy', 'capacity_available',
                     'medium_available', 'same_peer', 'commit_carrier', 'admit_link',
                     'candidate_used', 'candidate_class',
                     'reclaimable_carrier', 'reclaim_victim', 'candidate_room', 'ble_discovery_available',
                     'additional_candidate', 'setup_room', 'setup_capacity_available',
                     'plan_additional_candidate', 'incoming_standby_hint', 'maintain_incoming_demand',
                     'reclaim_for_incoming_probe', 'ble_admission_available', 'ble_probe_available',
                     'begin_setup', 'update_ble']
        prefix += structure(source, 'ble_seen')
        gate = '' if constrained_profile else incoming_pickup_gate()
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
