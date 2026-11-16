#include "wendy_net_alloc.h"
/* One bounded, device-authenticated app stream per TCP/TLS connection. */
#include "wendy_net_peer.h"
#if CONFIG_WENDY_NET_BLE
#include "wendy_ble_mesh.h"
#endif
#include "wendy_net_peer_protocol.h"
#include "wendy_pki_mesh.h"
#include "wendy_pki_work.h"
#include "wendy_net_profile.h"
#include "actor_driver.h"
#include "wendy_pki_verify.h"
#include "wendy_conf.h"
#if CONFIG_WENDY_NET
#include "wendy_net.h"
#endif
#include "esp_log.h"
#include "esp_heap_caps.h"
#include "esp_memory_utils.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "lwip/sockets.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define APP_PORT 43022
#ifndef CONFIG_WENDY_SERVER_PORT
#define CONFIG_WENDY_SERVER_PORT 5054
#endif
#define AGENT_PORT CONFIG_WENDY_SERVER_PORT
#include "app_relay.h"
#include "app_direct.h"
#include "wendy_net_direct_records.h"
#include "wendy_net_direct_guest_packet.h"
#include "wendy_net_direct_binding.h"
#include "wendy_net_direct_pki.h"
#include "mbedtls/platform_util.h"
#ifndef CONFIG_WENDY_NET_APP_MAX_FLOWS
#define CONFIG_WENDY_NET_APP_MAX_FLOWS 1
#endif
static atomic_bool starting, ready;
static atomic_uint inbound_flows, outbound_flows, inbound_regular;
/* Handshakes still use the single certificate worker. A resident relay owns
 * one admission slot, not the whole incoming/outgoing direction. */
static bool claim_flow_limit(atomic_uint *counter, unsigned limit)
{
    unsigned count = atomic_load(counter);
    do {
        if (count >= limit)
            return false;
    } while (!atomic_compare_exchange_weak(counter, &count, count + 1));
    return true;
}
static bool claim_flow(atomic_uint *counter)
{
    return claim_flow_limit(counter, CONFIG_WENDY_NET_APP_MAX_FLOWS);
}
static unsigned incoming_capacity(void)
{
    return CONFIG_WENDY_NET_APP_MAX_FLOWS + wn_app_direct_incoming_capacity();
}
static atomic_int listener = -1;
static const char *TAG = "wendy_net_app";

int wendy_net_app_direct_complete(int handle, int fd)
{
    atomic_fetch_sub(&outbound_flows, 1);
#if CONFIG_WENDY_NET
    return wendy_net_mesh_connected(handle, fd);
#else
    (void)handle;
    if (fd >= 0)
        close(fd);
    return -1;
#endif
}

/* The dial owner invokes this only after successful remote UDP admission.
 * Complete the guest and release its admission slot exactly once. */
int wendy_net_app_direct_datagram_complete(int handle, struct wn_direct_flows *flows, uint32_t id)
{
    atomic_fetch_sub(&outbound_flows, 1);
#if CONFIG_WENDY_NET
    struct wn_direct_flow *flow = wn_direct_flows_find(flows, id);
    struct wn_direct_packet_io io = {0};
    if (!flow || !flow->packet ||
        wn_direct_guest_packet_outgoing(handle, flow->request.datagram_size, &io)) {
        (void)wendy_net_mesh_connected(handle, -1);
        return -1;
    }
    if (wn_direct_flows_packet_io(flows, id, &io)) {
        io.close(io.context);
        return -1;
    }
    return 0;
#else
    (void)handle;
    (void)flows;
    (void)id;
    return -1;
#endif
}

/* Native WendyCom mTLS uses its signed agent endpoint directly. App TLS is
 * for guest services, not another wrapper around the agent's own TLS. */
struct app_control {
    struct wn_direct_peer *peer;
    uint64_t token, expected_serial;
    uint8_t address[16];
    uint16_t port;
    int64_t next_raw_attempt;
    bool (*eligible)(uint64_t serial, const uint8_t address[16], uint16_t port);
    struct wn_direct_records records;
};
/* Control records retain only their current partial read/write. This avoids
 * speculative maximum-size buffers at the post-TLS allocation peak. */
static void free_control(struct app_control *control)
{
    if (!control)
        return;
    wendy_net_free(control->records.tx);
    wendy_net_free(control->records.rx);
    wendy_net_free(control);
}
static void *control_resize(void *bytes, size_t size)
{
    if (!size) {
        wendy_net_free(bytes);
        return NULL;
    }
    void *next = wendy_net_realloc(bytes, size);
    return next;
}
static struct app_control *new_control(void)
{
    struct app_control *control = wendy_net_calloc(1, sizeof *control);
    if (control)
        control->records.resize = control_resize;
    return control;
}
struct app_raw {
    struct wn_direct_peer *peer;
    struct wn_direct_promoted_binding *binding;
    struct wn_direct_pki adapter;
    uint32_t id;
    uint64_t expected_serial, control_token;
    bool bound, retiring, drain;
    int64_t drain_deadline;
};
static struct app_raw *new_raw(void)
{
    struct app_raw *raw = wendy_net_calloc(1, sizeof *raw);
    if (raw)
        raw->binding = wendy_net_calloc(1, sizeof *raw->binding);
    if (!raw || !raw->binding) {
        wendy_net_free(raw);
        return NULL;
    }
    return raw;
}
static void free_raw(struct app_raw *raw)
{
    if (!raw)
        return;
    if (raw->binding) {
        mbedtls_platform_zeroize(raw->binding, sizeof *raw->binding);
        wendy_net_free(raw->binding);
    }
    mbedtls_platform_zeroize(raw, sizeof *raw);
    wendy_net_free(raw);
}
struct app_flow {
    wendy_pki_connection *connection;
    struct wendy_pki_mesh_identity identity;
    struct app_control *direct_control;
    struct app_raw *direct_raw;
    bool regular_claimed;
    int backend;
    bool outbound, native_agent, disposing;
    uint64_t config_generation;
    uint16_t datagram_max;
    uint16_t service_port;
    int guest_handle, listener_handle;
    uint8_t *datagram_in, *datagram_out;
    /* Guest TX arrives with raw heap ownership. Charge its transferred lifetime
     * explicitly; RX uses a managed pointer and passes its matching destructor. */
    wendy_net_memory_reservation_t datagram_out_charge;
    struct wna_channel channel;
    struct wna_session state;
    struct wendy_pki_net_setup *setup;
    struct wendy_pki_net_issuers issuers;
    atomic_bool job_done;
    int job_result, fd, pair_listener, pair_guest;
    bool connecting, backend_connecting, negotiated, local_half, tls_half;
    bool local_progress;
    unsigned phase;
    uint8_t request[64], response[8];
    size_t received, sent, wanted;
    char expected[37];
    struct buffer *buffers;
};
/* The actor keeps TCP and UDP flows in one intrusive list. Datagram buffers
 * are allocated on demand and remain owned by their authenticated flow. */
struct datagram_flow {
    struct app_flow flow;
    struct datagram_flow *next;
    uint8_t header[2], output_header[2];
    size_t header_used, received, wanted, outgoing, sent;
    int output_handle;
    unsigned inbound, outbound, last_in, last_out;
    int64_t activity;
};
static struct datagram_flow *datagram_flows;
static void app_actor_add(struct app_flow *);

/* Only actual pending packets own payload memory. Negotiating a large UDP
 * capacity does not reserve that capacity twice on an idle encrypted flow. */
static void *datagram_alloc(size_t size)
{
    return wendy_net_malloc(size ? size : 1);
}
/* One bounded nonblocking pass per flow; never wait on one peer while a
 * different peer has work. PKI read/write retain their lifetime checks. */
static int datagram_step(struct datagram_flow *d)
{
    struct app_flow *flow = &d->flow;
    wendy_pki_connection *c = flow->connection;
    if (!wendy_conf_is_current() || wendy_pki_reset_in_progress() ||
        esp_timer_get_time() - d->activity >= INT64_C(30000000))
        return -1;
#if CONFIG_WENDY_NET
    if (flow->outbound && !wendy_net_mesh_socket_live(flow->guest_handle))
        return -1;
    if (!flow->outbound &&
        wendy_net_guest_datagram_owner(flow->service_port) != flow->listener_handle)
        return -1;
#endif
    bool progress = false;
    if (d->header_used < 2) {
        ssize_t n = wendy_pki_read(c, d->header + d->header_used, 2 - d->header_used);
        if (n > 0) {
            d->header_used += n;
            progress = true;
            if (d->header_used == 2) {
                d->wanted = wn_get16(d->header);
                if (d->wanted > flow->datagram_max)
                    return -1;
    }
        } else if (!n || (n != -2 && n != -3))
            return -1;
    }
    if (d->header_used == 2 && !flow->datagram_in) {
        flow->datagram_in = datagram_alloc(d->wanted);
        if (!flow->datagram_in) {
            ESP_LOGW(TAG, "UDP input allocation failed: bytes=%u heap=%u largest=%u",
                     (unsigned)d->wanted, (unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT),
                (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
            return -1;
        }
    }
    if (d->header_used == 2 && d->received < d->wanted) {
        ssize_t n = wendy_pki_read(c, flow->datagram_in + d->received, d->wanted - d->received);
        if (n > 0) {
            d->received += n;
            progress = true;
        } else if (!n || (n != -2 && n != -3))
            return -1;
    }
    if (d->header_used == 2 && d->received == d->wanted) {
#if CONFIG_WENDY_NET
        int delivered =
            flow->outbound
                ? wendy_net_mesh_datagram_receive_owned(flow->guest_handle, &flow->datagram_in,
                                                        d->wanted, wendy_net_free)
                : wendy_net_guest_datagram_deliver_owned(flow->listener_handle, &flow->guest_handle,
                                                         &flow->datagram_in, d->wanted,
                                                         flow->datagram_max, wendy_net_free);

        if (delivered < 0)
            return -1;
        if (delivered) {
            d->inbound++;
            d->last_in = (unsigned)d->wanted;
            d->header_used = d->received = d->wanted = 0;
            progress = true;
        }
#else
        return -1;
#endif
    }
    if (!flow->datagram_out) {
#if CONFIG_WENDY_NET
        size_t length = 0;
        int taken = wendy_net_guest_datagram_take(flow->guest_handle, &flow->datagram_out, &length);
        if (taken < 0)
            return -1;
        if (taken) {
            d->output_handle = flow->guest_handle;
            if (length > flow->datagram_max)
                return -1;
            if (!wendy_net_memory_reserve(
                    wendy_net_runtime_memory_ledger(), &flow->datagram_out_charge,
                    wendy_net_memory_charge(length ? length : 1),
                    esp_ptr_external_ram(flow->datagram_out) ? WENDY_NET_MEMORY_EXTERNAL
                                                             : WENDY_NET_MEMORY_INTERNAL))
                return -1;
            d->outbound++;
            d->last_out = (unsigned)length;
            wn_put16(d->output_header, (uint16_t)length);
            d->outgoing = length + 2;
            d->sent = 0;
            progress = true;
        }
#endif
    }
    if (d->sent < d->outgoing) {
        size_t chunk;
        const uint8_t *data;
        if (d->sent < 2) {
            data = d->output_header + d->sent;
            chunk = 2 - d->sent;
        } else {
            data = flow->datagram_out + d->sent - 2;
            chunk = d->outgoing - d->sent;
            if (chunk > 1024)
                chunk = 1024;
        }
        ssize_t n = wendy_pki_write(c, data, chunk);
        if (n > 0) {
            d->sent += n;
            progress = true;
            if (d->sent == d->outgoing) {
                free(flow->datagram_out);
                flow->datagram_out = NULL;
                wendy_net_memory_release(&flow->datagram_out_charge);
                d->sent = d->outgoing = 0;
#if CONFIG_WENDY_NET
                wendy_net_guest_datagram_sent(d->output_handle);
#endif
            }
        } else if (!n || (n != -2 && n != -3))
            return -1;
    }
    if (progress)
        d->activity = esp_timer_get_time();
    return progress ? 1 : 0;
}

static void close_flow(struct app_flow *flow)
{
#if CONFIG_WENDY_NET
    /* Before WAU/WAS negotiation there is no native datagram association or
     * loopback stream yet. Complete the pending guest connect explicitly so
     * ordinary route loss/peer restart does not leave it resolving forever. */
    if (flow->outbound && flow->guest_handle > 0 && !flow->negotiated) {
        ESP_LOGI(
            TAG,
            "outgoing VIP setup closed: peer=%s phase=%u connecting=%u channel_failed=%u result=%d",
            flow->expected, (unsigned)flow->state.phase, (unsigned)flow->connecting,
            (unsigned)flow->channel.failed, flow->job_result);
        wendy_net_mesh_connected(flow->guest_handle, -1);
    } else if (flow->datagram_max)
        wendy_net_guest_datagram_closed(flow->guest_handle);
#endif
    if (flow->state.lent)
        abort();
    if (flow->backend >= 0)
        close(flow->backend);
    if (flow->fd >= 0)
        close(flow->fd);
    if (flow->pair_listener >= 0)
        close(flow->pair_listener);
    if (flow->pair_guest >= 0)
        close(flow->pair_guest);
    assert(!flow->setup && !flow->connection);
    wnad_handshake_release(flow);
    wendy_net_free(flow->buffers);
    bool outbound = flow->outbound;
    if (flow->regular_claimed)
        atomic_fetch_sub(&inbound_regular, 1);
    wendy_net_free(flow->datagram_in);
    free(flow->datagram_out);
    wendy_net_memory_release(&flow->datagram_out_charge);
    wendy_net_free(flow);
    atomic_fetch_sub(outbound ? &outbound_flows : &inbound_flows, 1);
}
static int64_t app_handshake_budget(void)
{
#if CONFIG_WENDY_NET_BLE
    if (wble_mesh_profile() == 2)
        return INT64_C(240000000);
#endif
    return INT64_C(120000000);
}
#if CONFIG_WENDY_NET
struct guest_connect {
    int handle;
    char peer[37];
    uint16_t port;
    bool datagram, upper_only;
    int64_t deadline;
};

/* A loopback pair lets the existing guest socket task retain its buffers,
 * readiness notifications and cleanup. Only the native relay owns TLS. */
static struct guest_connect *pending_guest;
static pthread_mutex_t request_lock = PTHREAD_MUTEX_INITIALIZER;

bool wendy_net_app_peer_outgoing_busy_now(const char *peer)
{
    if (!peer)
        return true;
    for (struct datagram_flow *d = datagram_flows; d; d = d->next)
        if (d->flow.outbound && !strcmp(d->flow.expected, peer))
            return true;
    /* pending_guest has not selected or opened a transport. The actor can
     * assign that request to the new epoch; the admission gate below prevents
     * it from starting an upper connection while a proposal is reserved. */
    return false;
}

/* Requeue an unadmitted direct UDP request without claiming or releasing its
 * existing outbound slot. Queue pressure leaves ownership with the dial job. */
int wendy_net_app_direct_datagram_fallback(int handle, const char *peer, uint16_t port,
                                           int64_t deadline)
{
    struct guest_connect *q = wendy_net_calloc(1, sizeof *q);
    if (!q)
        return -1;
    *q = (struct guest_connect){
        .handle = handle, .port = port, .datagram = true, .upper_only = true, .deadline = deadline};
    memcpy(q->peer, peer, sizeof q->peer);
    pthread_mutex_lock(&request_lock);
    bool accepted = atomic_load(&ready) && !pending_guest;
    if (accepted)
        pending_guest = q;
    pthread_mutex_unlock(&request_lock);
    if (!accepted) {
        wendy_net_free(q);
        return -1;
    }
    wnad_wake();
    return 0;
}
static int guest_mesh_resolve(const char *host, uint8_t address[16])
{
    uint8_t uuid[16];
    int recognized = wn_device_hostname_parse(host, uuid);
    if (recognized <= 0)
        return recognized;
    if (!wendy_conf_is_current() || wendy_pki_reset_in_progress())
        return -1;
    wn_address(uuid, address);
    return 1;
}
static int guest_mesh_begin(int handle, const char *host, uint16_t port, bool datagram)
{
    if (!atomic_load(&ready))
        return -1;
    uint8_t uuid[16];
    int recognized = wn_device_hostname_parse(host, uuid);
    if (recognized <= 0)
        return recognized;
    if (!wendy_conf_is_current() || wendy_pki_reset_in_progress())
        return -1;
    char peer[37];
    wn_uuid_format(uuid, peer);
    char tenant[37], self[65];
    wendy_conf_get_enrolled_ids(tenant, self);
    if (!strcmp(peer, self)) {
        /* The current guest already owns both ends of this local service.
         * Reuse its listener bridge instead of queueing a client handshake
         * whose server would need the same serialized TLS worker. Listener
         * lookup and completion retain the ordinary stop/reset ownership. */
        int owner = -1;
        int fd = datagram ? wendy_net_guest_datagram_connect(port, &owner)
                        : wendy_net_guest_service_connect(port);
        (void)wendy_net_mesh_connected(handle, fd);
        return 1;
    }
    if (!claim_flow(&outbound_flows))
        return -1;
    struct guest_connect *request = wendy_net_calloc(1, sizeof *request);
    if (request) {
        request->handle = handle;
        request->port = port;
        request->datagram = datagram;
        request->deadline = esp_timer_get_time() + app_handshake_budget();
        memcpy(request->peer, peer, sizeof peer);
        pthread_mutex_lock(&request_lock);
        bool accepted = atomic_load(&ready) && pending_guest == NULL;
        if (accepted)
            pending_guest = request;
        pthread_mutex_unlock(&request_lock);
        if (accepted) {
            wnad_wake();
            return 1;
    }
    }
    wendy_net_free(request);
    atomic_fetch_sub(&outbound_flows, 1);
    return -1;
}
#endif
/* Accepted VIPs and all established TCP/UDP relays are actor-owned. */
static struct app_flow *new_flow(int fd, bool outbound)
{
    struct datagram_flow *d = wendy_net_calloc(1, sizeof *d);
    if (!d)
        return NULL;
    struct app_flow *f = &d->flow;
    f->fd = fd;
    f->outbound = outbound;
    f->backend = f->pair_listener = f->pair_guest = -1;
    atomic_init(&f->job_done, false);
    f->state = (struct wna_session){.phase = WNA_PREPARE,
                                    .deadline = (uint64_t)esp_timer_get_time() +
                                                (uint64_t)app_handshake_budget()};
    f->wanted = 6;
    return f;
}
static void app_actor_add(struct app_flow *flow)
{
    struct datagram_flow *d = (struct datagram_flow *)flow;
    d->activity = esp_timer_get_time();
    d->next = datagram_flows;
    datagram_flows = d;
}
int wn_app_direct_promote(uint64_t serial, const char peer[37], const uint8_t address[16],
                          uint16_t port,
                          bool (*eligible)(uint64_t serial, const uint8_t address[16],
                                           uint16_t port))
{
    uint8_t uuid[16];
    if (!serial || !peer || !address || !port || !eligible || !eligible(serial, address, port) ||
        wn_uuid_parse(peer, uuid) || !atomic_load(&ready) || !wendy_conf_is_current())
        return -1;
    for (struct datagram_flow *d = datagram_flows; d; d = d->next) {
        struct app_control *c = d->flow.direct_control;
        if (c && c->expected_serial == serial && !d->flow.disposing)
            return 1;
    }
    if (!claim_flow_limit(&outbound_flows, incoming_capacity()))
        return -1;
    struct app_flow *f = new_flow(-1, true);
    if (!f) {
        atomic_fetch_sub(&outbound_flows, 1);
        return -1;
    }
    f->direct_control = new_control();
    if (!f->direct_control) {
        close_flow(f);
        return -1;
    }
    f->direct_control->expected_serial = serial;
    f->direct_control->eligible = eligible;
    memcpy(f->direct_control->address, address, 16);
    f->direct_control->port = port;
    memcpy(f->expected, peer, 37);
    char host[INET6_ADDRSTRLEN];
    if (inet_ntop(AF_INET6, address, host, sizeof host))
        f->fd = wnad_connect(host, port, &f->connecting);
    if (f->fd < 0) {
        free_control(f->direct_control);
        f->direct_control = NULL;
        close_flow(f);
        return -1;
    }
    app_actor_add(f);
    return 0;
}
/* The physical control dialer opens every raw stream; the accepting peer
 * waits for WDP1, matching WendyOS's dispatcher election. */
static struct app_control *raw_control(const struct app_raw *r)
{
    for (struct datagram_flow *d = datagram_flows; d; d = d->next) {
        struct app_flow *f = &d->flow;
        struct app_control *c = f->direct_control;
        if (!f->disposing && f->outbound && f->negotiated && c && c->peer &&
            c->expected_serial == r->expected_serial && c->token == r->control_token &&
            !c->peer->session.closed && c->peer->session.active &&
            c->peer->session.token == c->token)
            return c;
    }
    return NULL;
}
static int schedule_promoted_raw(void)
{
    int64_t now = esp_timer_get_time();
    for (struct datagram_flow *d = datagram_flows; d; d = d->next) {
        struct app_flow *owner = &d->flow;
        struct app_control *c = owner->direct_control;
        if (!owner->outbound || !owner->negotiated || owner->disposing || !c || !c->peer ||
            c->peer->session.closed || !c->peer->session.active ||
            c->peer->session.token != c->token)
            continue;
        struct wn_direct_flows *flows = &c->peer->flows;
        for (unsigned i = 0; i < 2u * flows->slots; i++) {
            struct wn_direct_flow *flow = &flows->flows[i];
            struct wn_direct_open_entry entry;
            if (!flow->id || flow->reset || flow->promoted || flow->binding ||
                (!flow->has_lane && !flow->packet) ||
                wn_direct_flows_open(flows, flow->id, &entry) ||
                !entry.complete || entry.result || entry.local_closed || entry.remote_closed)
                continue;
            bool exists = false;
            for (struct datagram_flow *at = datagram_flows; at; at = at->next) {
                struct app_raw *r = at->flow.direct_raw;
                if (r && r->expected_serial == c->expected_serial && r->id == flow->id) {
                    exists = true;
                    break;
                }
            }
            if (exists)
                continue;
            if (now >= (int64_t)owner->state.deadline) {
                (void)wn_direct_flows_reset(flows, flow->id, WN_DIRECT_IO);
                return 1;
            }
            if (now < c->next_raw_attempt)
                return 0;
            c->next_raw_attempt = now + 50000;
            if (!claim_flow_limit(&outbound_flows, incoming_capacity()))
                return 0;
            struct app_flow *f = new_flow(-1, true);
            if (!f) {
                atomic_fetch_sub(&outbound_flows, 1);
                return 0;
            }
            f->direct_raw = new_raw();
            if (!f->direct_raw) {
                close_flow(f);
                return 0;
            }
            f->direct_raw->id = flow->id;
            f->direct_raw->expected_serial = c->expected_serial;
            f->direct_raw->control_token = c->token;
            f->state.deadline = owner->state.deadline;
            memcpy(f->expected, owner->expected, 37);
            memcpy(f->request, "WDP1", 4);
            memcpy(f->request + 4, c->peer->session.binding.session_id, 32);
            uint64_t generation = c->peer->session.exchange.attachment.generation;
            for (unsigned j = 0; j < 8; j++)
                f->request[36 + j] = (uint8_t)(generation >> (56 - 8 * j));
            wn_put32(f->request + 44, flow->id);
            char host[INET6_ADDRSTRLEN];
            if (inet_ntop(AF_INET6, c->address, host, sizeof host))
                f->fd = wnad_connect(host, c->port, &f->connecting);
            if (f->fd < 0) {
                free_raw(f->direct_raw);
                f->direct_raw = NULL;
                close_flow(f);
                return 0;
            }
            app_actor_add(f);
            return 1; /* Mutate the list only outside its poll traversal. */
        }
    }
    return 0;
}
void wendy_net_app_accept(int fd)
{
    if (!wendy_conf_is_current() || !claim_flow_limit(&inbound_flows, incoming_capacity())) {
        close(fd);
        return;
    }
    struct app_flow *flow = new_flow(fd, false);
    int flags = fcntl(fd, F_GETFL, 0);
    if (!flow || fd >= FD_SETSIZE || flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        wendy_net_free(flow);
        close(fd);
        atomic_fetch_sub(&inbound_flows, 1);
        return;
    }
    app_actor_add(flow);
}
/* The remote input half may close while the guest still produces a reply.
 * EOF belongs only to the read BIO; output remains valid until socket I/O
 * fails or the flow is explicitly disposed. */
static ssize_t app_write_bio(void *context, const void *bytes, size_t size)
{
    struct wna_channel *channel = context;
    if (channel->failed)
        return -1;
    size_t room = wna_buffer_space(&channel->output);
    if (!room)
        return -3;
    if (size > room)
        size = room;
    memcpy(channel->output.bytes + channel->output.size, bytes, size);
    channel->output.size += size;
    return (ssize_t)size;
}
static void app_setup_work(void *context)
{
    struct app_flow *f = context;
    if (f->disposing) {
        wendy_pki_net_dispose(f->setup);
        f->setup = NULL;
        wendy_pki_net_release_issuers(&f->issuers);
        wendy_pki_close(f->connection);
        f->connection = NULL;
        f->job_result = 0;
    } else if (f->state.phase == WNA_PREPARE) {
        struct wendy_pki_stream bio = {
            .context = &f->channel, .read = wna_read, .write = app_write_bio, .wait = wnad_no_wait};
        esp_err_t result = wendy_pki_net_begin(
            &bio, !f->outbound, f->expected[0] ? f->expected : NULL, true, &f->setup);
        if (result == ESP_OK)
            wendy_pki_net_add_issuers(f->setup, &f->issuers);
        else
            wendy_pki_net_release_issuers(&f->issuers);
        f->job_result = result == ESP_OK                                          ? 0
                        : (result == ESP_ERR_TIMEOUT || result == ESP_ERR_NO_MEM) ? 2
                                                                                  : -1;
    } else
        f->job_result = wendy_pki_net_step(f->setup);
    atomic_store(&f->job_done, true);
}
/* Before a binding can commit, only this candidate owns the claim. Releasing
 * it permits another authenticated candidate without losing retained bytes.
 * After possible commit the peer may already use raw bytes: fail closed. */
static void release_raw_binding(struct app_raw *r)
{
    if (!r->peer)
        return;
    struct wn_direct_flow *flow = wn_direct_flows_find(&r->peer->flows, r->id);
    if (!flow)
        return;
    if (flow->upper.context == &r->adapter ||
        (flow->binding == r->binding && r->binding->commit_possible))
        (void)wn_direct_flows_reset(&r->peer->flows, r->id, WN_DIRECT_IO);
    else if (flow->binding == r->binding)
        flow->binding = NULL;
}
/* TLS destruction may touch the same crypto allocator/key tables as setup.
 * Lend cleanup to the single worker too, after collecting any earlier loan. */
static bool dispose_flow(struct app_flow *f)
{
    if (f->state.lent) {
        if (!atomic_load_explicit(&f->job_done, memory_order_acquire))
            return false;
        f->state.lent = false;
    }
    if (!f->disposing) {
        if (f->direct_raw) {
            struct app_raw *r = f->direct_raw;
            if (r->peer) {
                release_raw_binding(r);
                wn_app_direct_flow_release(r->peer);
            }
            free_raw(r);
            f->direct_raw = NULL;
        }
        if (f->direct_control) {
            wn_app_direct_control_close(f->direct_control->peer, f->direct_control->token);
            free_control(f->direct_control);
            f->direct_control = NULL;
        }
        f->disposing = true;
        f->state.cancel = true;
        if (f->fd >= 0) {
            close(f->fd);
            f->fd = -1;
    }
        if (f->backend >= 0) {
            close(f->backend);
            f->backend = -1;
        }
        if (f->pair_listener >= 0) {
            close(f->pair_listener);
            f->pair_listener = -1;
        }
        if (f->pair_guest >= 0) {
            close(f->pair_guest);
            f->pair_guest = -1;
        }
    }
    if (f->setup || f->connection) {
        atomic_store(&f->job_done, false);
        if (wendy_pki_work_submit(app_setup_work, f)) {
            f->state.lent = true;
        }
        return false;
    }
    wendy_pki_net_release_issuers(&f->issuers);
    close_flow(f);
    return true;
}
static int tls_transfer(struct app_flow *f, uint8_t *bytes, size_t size, size_t *offset,
                        bool writing)
{
    if (*offset >= size)
        return 0;
    ssize_t n = writing ? wendy_pki_write(f->connection, bytes + *offset, size - *offset)
                        : wendy_pki_read(f->connection, bytes + *offset, size - *offset);
    if (n > 0) {
        *offset += (size_t)n;
        return *offset == size ? 0 : 1;
    }
    return n == -2 || n == -3 ? 1 : -1;
}
static int begin_pair(struct app_flow *f)
{
    if (f->pair_listener >= 0)
        return 0;
    f->pair_listener = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t size = sizeof address;
    if (f->pair_listener < 0 || f->pair_listener >= FD_SETSIZE ||
        fcntl(f->pair_listener, F_SETFL, O_NONBLOCK) < 0 ||
        bind(f->pair_listener, (struct sockaddr *)&address, size) ||
        getsockname(f->pair_listener, (struct sockaddr *)&address, &size) ||
        listen(f->pair_listener, 1))
        return -1;
    bool connecting;
    f->pair_guest = wnad_connect("127.0.0.1", ntohs(address.sin_port), &connecting);
    return f->pair_guest < 0 ? -1 : 0;
}
static int raw_export(void *arg, const char *label, const uint8_t context[32], uint8_t out[32])
{
    if (strcmp(label, WN_DIRECT_PROMOTED_EXPORT_LABEL))
        return -1;
    return wendy_pki_promoted_flow_binding(arg, context, out);
}
static bool raw_pending(void *arg)
{
    struct app_flow *f = arg;
    return f->channel.input.size || f->channel.eof;
}
static void raw_retire(void *arg, bool drain)
{
    struct app_flow *f = arg;
    struct app_raw *r = f->direct_raw;
    r->retiring = true;
    r->drain = drain;
    r->drain_deadline = esp_timer_get_time() + INT64_C(30000000);
}
static int control_read(void *, uint8_t *, size_t);
static int control_write(void *, const uint8_t *, size_t);
static int raw_negotiate(struct app_flow *f)
{
    struct app_raw *r = f->direct_raw;
    int64_t now = esp_timer_get_time();
    if (!r->peer) {
        int result = wn_app_direct_flow_pin(f->connection, &f->identity, f->request, &r->peer);
        if (result) {
            if (result < 0)
                ESP_LOGW(TAG, "promoted stream rejected: stage=pin result=%d", result);
            return result;
        }
        if (f->outbound &&
            (r->peer->serial != r->expected_serial || r->peer->session.token != r->control_token)) {
            wn_app_direct_flow_release(r->peer);
            r->peer = NULL;
            return -1;
        }
        r->id = wn_get32(f->request + 44);
        result = wn_direct_session_start_binding(&r->peer->session, r->id, r->binding, f->outbound,
                                                 raw_export, f->connection, now);
        if (result) {
            if (result != WN_DIRECT_CAPACITY)
                ESP_LOGW(TAG, "promoted stream rejected: stage=start flow=%u result=%d",
                         (unsigned)r->id, result);
            wn_app_direct_flow_release(r->peer);
            r->peer = NULL;
            return result == WN_DIRECT_CAPACITY ? 1 : -1;
        }
        size_t used = 0;
        if (!f->outbound &&
            (wn_direct_promoted_input(r->binding, f->request, 64, &used) || used != 64)) {
            ESP_LOGW(TAG, "promoted stream rejected: stage=hello flow=%u", (unsigned)r->id);
            return -1;
        }
    }
    struct wn_direct_flow *flow = wn_direct_flows_find(&r->peer->flows, r->id);
    if (r->peer->session.closed || !flow || flow->binding != r->binding) {
        ESP_LOGW(TAG, "promoted stream rejected: stage=owner flow=%u", (unsigned)r->id);
        return -1;
    }
    struct wn_direct_upper io = {
        .context = f->connection, .read = control_read, .write = control_write};
    int binding_progress = wn_direct_promoted_poll(r->binding, &io);
    if (binding_progress < 0) {
        ESP_LOGW(TAG, "promoted stream rejected: stage=binding flow=%u state=%u failed=%u",
                 (unsigned)r->id, r->binding->state, r->binding->failed);
        return -1;
    }
    f->local_progress = binding_progress > 0;
    if (!r->binding->done)
        return 1;
    r->adapter = (struct wn_direct_pki){
        .connection = f->connection, .owner = f, .retire = raw_retire, .pending = raw_pending};
    struct wn_direct_upper upper = wn_direct_pki_upper(&r->adapter);
    int result = wn_direct_session_commit_flow(&r->peer->session, r->id, r->binding, &upper, now);
    if (result) {
        ESP_LOGW(TAG, "promoted stream rejected: stage=commit flow=%u result=%d", (unsigned)r->id,
                 result);
        return -1;
    }
    r->bound = true;
    f->negotiated = true;
    return 0;
}
static int negotiate(struct app_flow *f)
{
    if (f->outbound && f->direct_raw)
        return raw_negotiate(f);
    if (f->outbound && f->direct_control) {
        struct app_control *c = f->direct_control;
        if (!c->peer) {
            int result = wn_app_direct_control_begin(f->connection, &f->identity, NULL, true,
                                                     c->expected_serial, &c->peer, &c->token);
            if (result)
                return result;
            memcpy(f->request, "WDC1", 4);
            if (wn_uuid_parse(f->identity.device, f->request + 4))
                return -1;
        }
        if (c->peer->session.closed || c->peer->session.token != c->token)
            return -1;
        int result = tls_transfer(f, f->request, 20, &f->sent, true);
        if (result)
            return result;
        f->negotiated = true;
        return 0;
    }
    if (f->outbound) {
        int r = tls_transfer(f, f->request, f->datagram_max ? 8 : 6, &f->sent, true);
        if (r)
            return r;
        r = tls_transfer(f, f->response, f->datagram_max ? 8 : 1, &f->received, false);
        if (r)
            return r;
        if (f->datagram_max) {
            unsigned maximum = wn_get16(f->response + 6);
            if (memcmp(f->response, "WUA3", 4) || f->response[4] != 1 || f->response[5] != 3 ||
                !maximum || maximum > f->datagram_max)
                return -1;
            f->datagram_max = (uint16_t)maximum;
#if CONFIG_WENDY_NET
            if (wendy_net_mesh_datagram_connected(f->guest_handle, maximum))
                return -1;
#else
            return -1;
#endif
        } else {
            if (f->response[0] != 1 || begin_pair(f))
                return -1;
            if (f->backend < 0) {
                f->backend = accept(f->pair_listener, NULL, NULL);
                if (f->backend < 0)
                    return errno == EAGAIN || errno == EWOULDBLOCK ? 1 : -1;
                if (f->backend >= FD_SETSIZE || fcntl(f->backend, F_SETFL, O_NONBLOCK) < 0)
                    return -1;
                close(f->pair_listener);
                f->pair_listener = -1;
#if CONFIG_WENDY_NET
                wendy_net_mesh_connected(f->guest_handle, f->pair_guest);
                f->pair_guest = -1;
#else
                return -1;
#endif
            }
        }
    } else {
        int r = tls_transfer(f, f->request, f->wanted, &f->received, false);
        if (r)
            return r;
        if (!f->phase && !memcmp(f->request, "WDP1", 4)) {
            f->wanted = 64;
            if (f->received < f->wanted)
                return 1;
            if (!f->direct_raw) {
                f->direct_raw = new_raw();
                if (!f->direct_raw)
                    return -1;
            }
            return raw_negotiate(f);
        }
        if (!f->phase && !memcmp(f->request, "WDC1", 4)) {
            f->wanted = 20;
            if (f->received < f->wanted)
                return 1;
            if (!f->direct_control) {
                f->direct_control = new_control();
                if (!f->direct_control)
                    return -1;
            }
            int result =
                wn_app_direct_control_begin(f->connection, &f->identity, f->request + 4, false, 0,
                                            &f->direct_control->peer, &f->direct_control->token);
            if (result)
                return result;
            f->negotiated = true;
            return 0;
        }
        if (!f->phase) {
            if (!f->regular_claimed) {
                if (!claim_flow(&inbound_regular))
                    return -1;
                f->regular_claimed = true;
            }
            f->service_port = wn_get16(f->request + 4);
            if (!memcmp(f->request, "WAU3", 4)) {
                f->wanted = 8;
                if (f->received < 8)
                    return 1;
#if CONFIG_WENDY_NET
                unsigned maximum = wn_get16(f->request + 6);
                if (maximum > wendy_net_guest_datagram_capacity())
                    maximum = wendy_net_guest_datagram_capacity();
                if (maximum > 65507)
                    maximum = 65507;
                f->listener_handle = wendy_net_guest_datagram_owner(f->service_port);
                if (!maximum || f->listener_handle <= 0)
                    return -1;
                f->datagram_max = (uint16_t)maximum;
                memcpy(f->response, "WUA3", 4);
                f->response[4] = 1;
                f->response[5] = 3;
                wn_put16(f->response + 6, f->datagram_max);
#else
                return -1;
#endif
            } else {
                if (memcmp(f->request, "WAS1", 4))
                    return -1;
                if (f->service_port == AGENT_PORT)
                    return -1;
#if CONFIG_WENDY_NET
                f->backend = wendy_net_guest_service_begin(f->service_port);
                f->backend_connecting = f->backend >= 0;
#endif
                if (f->backend < 0)
                    return -1;
                f->response[0] = 1;
            }
            f->phase = 1;
        }
        if (f->backend_connecting) {
            int connected = wnad_connected(f->backend);
            if (connected <= 0)
                return connected ? -1 : 1;
            f->backend_connecting = false;
        }
        r = tls_transfer(f, f->response, f->datagram_max ? 8 : 1, &f->sent, true);
        if (r)
            return r;
    }
    if (!f->datagram_max && !f->buffers) {
        f->buffers = wendy_net_calloc(2, sizeof *f->buffers);
        if (!f->buffers)
            return -1;
    }
    f->negotiated = true;
    ((struct datagram_flow *)f)->activity = esp_timer_get_time();
    ESP_LOGI(TAG,
             "actor VIP ready: peer=%s port=%u udp=%u heap=%u internal_min=%u internal_largest=%u",
             f->expected, (unsigned)f->service_port, (unsigned)f->datagram_max,
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT),
             (unsigned)heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),
             (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT));
    return 0;
}
static int relay_step(struct app_flow *f)
{
    return wn_app_relay_step(f->connection, f->backend, f->buffers, &f->local_half, &f->tls_half,
                             f->channel.output.size != 0);
}
static int control_read(void *arg, uint8_t *bytes, size_t size)
{
    return (int)wendy_pki_read(arg, bytes, size);
}
static int control_write(void *arg, const uint8_t *bytes, size_t size)
{
    return (int)wendy_pki_write(arg, bytes, size);
}
static int control_open(void *arg, uint32_t id)
{
    return wn_app_direct_open(arg, id);
}
static int app_step(struct app_flow *f, int64_t now)
{
    f->local_progress = false;
    if (f->state.lent) {
        if (!atomic_load(&f->job_done))
            return 0;
        wna_completed(&f->state, f->job_result);
        if (f->job_result == 2) {
            f->state.retry_at = (uint64_t)now + 50000;
            wnad_handshake_release(f);
    }
    }
    if (f->state.cancel || !wendy_conf_is_current() || wendy_pki_reset_in_progress() ||
        (f->connection && !wendy_conf_snapshot_current(f->config_generation)))
        return -1;
    if (!f->negotiated && now >= (int64_t)f->state.deadline)
        return -1;
    if (f->outbound && f->direct_control && !f->negotiated &&
        !f->direct_control->eligible(f->direct_control->expected_serial, f->direct_control->address,
                                     f->direct_control->port))
        return -1;
    if (f->outbound && f->direct_raw && !f->negotiated && !raw_control(f->direct_raw))
        return -1;
    if (f->connecting) {
        int r = wnad_connected(f->fd);
        if (r <= 0)
            return r;
        f->connecting = false;
    }
    if (f->native_agent) {
        /* Transfer the connected raw stream to the guest. WendyCom's client
         * and native agent retain their one end-to-end TLS session. */
#if CONFIG_WENDY_NET
        wendy_net_mesh_connected(f->guest_handle, f->fd);
        f->fd = -1;
        f->negotiated = true;
#endif
        return -1;
    }
    int progress = wnad_channel_io(&f->channel, f->fd, NULL);
    if (progress < 0)
        return -1;
    if (f->state.phase != WNA_READY) {
        enum wna_effect e =
            wna_next(&f->state, (uint64_t)now, f->channel.input.size || f->channel.eof,
                     wna_buffer_space(&f->channel.output) != 0);
        if (e == WNA_CLOSE)
            return -1;
        if (e == WNA_CRYPTO_PREPARE && !wnad_handshake_claim(f))
            return progress;
        if (e == WNA_CRYPTO_PREPARE || e == WNA_CRYPTO_STEP) {
            if (e == WNA_CRYPTO_PREPARE && !f->issuers.release)
                wendy_net_peer_issuer_snapshot(&f->issuers);
            atomic_store(&f->job_done, false);
            if (wendy_pki_work_submit(app_setup_work, f)) {
                wna_lend(&f->state);
            }
        }
        return progress;
    }
    if (!f->connection) {
        f->connection = wendy_pki_net_take(f->setup, &f->identity);
        if (!f->connection)
            return -1; /* failed take retains setup ownership */
        f->setup = NULL;
        f->config_generation = f->identity.config_generation;
        wnad_handshake_release(f);
        if (!wendy_conf_snapshot_current(f->config_generation))
            return -1;
    }
    if (!f->negotiated) {
        if (now >= (int64_t)f->state.deadline)
            return -1;
        if (negotiate(f) < 0)
            return -1;
        /* A completed binding flight can leave the next flight runnable with
         * no bytes in either BIO. A new control also needs its first poll.
         * negotiate's positive return means waiting, not actual progress. */
        f->local_progress |= f->negotiated;
        return progress || f->local_progress;
    }
    if (f->direct_raw) {
        struct app_raw *r = f->direct_raw;
        if (r->retiring) {
            if (!r->drain || !f->channel.output.size || now >= r->drain_deadline)
                return -1;
            return progress;
        }
        if (r->peer->session.closed)
            return -1;
        return progress; /* retained actor owns the plaintext pump */
    }
    if (f->direct_control) {
        struct app_control *c = f->direct_control;
        if (!c->records.queued && !c->records.received && !f->channel.output.size &&
            wn_direct_session_retire(&c->peer->session))
            return -1;
        struct wn_direct_upper io = {
            .context = f->connection, .read = control_read, .write = control_write};
        int result = wn_direct_records_poll(&c->records, &c->peer->session, c->token, &io, now,
                                            control_open, c->peer);
        return result < 0 ? -1 : progress || result;
    }
    int r = f->datagram_max ? datagram_step((struct datagram_flow *)f) : relay_step(f);
    return r < 0 ? -1 : progress || r;
}
bool wendy_net_app_yield_setup(void)
{
    bool changed = false;
    for (struct datagram_flow *d = datagram_flows; d; d = d->next) {
        struct app_flow *f = &d->flow;
        if (wna_yield_guest_setup(&f->state, WENDY_NET_NON_TRANSIT, f->outbound,
            f->connection || f->negotiated || f->native_agent,
                                  wendy_pki_handshake_owned(f))) {
            ESP_LOGI(TAG,
                     "yielding outgoing guest TLS setup for native management: peer=%s lent=%u",
                     f->expected, (unsigned)f->state.lent);
            changed = true;
        }
    }
    return changed;
}
bool wendy_net_app_yield_incoming_setup(void)
{
    bool changed = false;
    for (struct datagram_flow *d = datagram_flows; d; d = d->next) {
        struct app_flow *f = &d->flow;
        /* No destination socket has been opened at this point. Reuse deferred
         * actor cancellation: a crypto loan must finish before TLS is freed. */
        if (!f->outbound && wna_yield_guest_setup(&f->state, WENDY_NET_NON_TRANSIT, true,
                                                  f->connection || f->negotiated || f->native_agent,
                                                  wendy_pki_handshake_owned(f))) {
            ESP_LOGI(TAG, "yielding incoming VIP TLS setup for carrier recovery: lent=%u",
                     (unsigned)f->state.lent);
            changed = true;
        }
    }
    return changed;
}
static bool incoming_admission_ready(void)
{
    if (atomic_load(&inbound_flows) >= incoming_capacity())
        return false;
    return true;
}
int wendy_net_app_poll(void)
{
    int fd = atomic_load(&listener), progress = 0;
    if (fd >= 0 && incoming_admission_ready()) {
        int incoming = accept(fd, NULL, NULL);
        if (incoming >= 0) {
            wendy_net_app_accept(incoming);
            progress = 1;
        }
    }
#if CONFIG_WENDY_NET
    pthread_mutex_lock(&request_lock);
    struct guest_connect *q = pending_guest;
    /* Keep ownership of the bounded request slot while a reuse proposal is
     * reserved. Taking then requeueing it could let a concurrent caller steal
     * the slot and turn a harmless epoch transition into an app failure. */
    if (q && wendy_net_peer_upper_blocked_now(q->peer) && esp_timer_get_time() < q->deadline)
        q = NULL;
    else
        pending_guest = NULL;
    pthread_mutex_unlock(&request_lock);
    if (q && !q->upper_only &&
        wendy_net_peer_direct_connect_now(q->peer, q->port, q->datagram, q->handle, q->deadline)) {
        wendy_net_free(q);
        q = NULL;
        progress = 1;
    }
    if (q) {
        uint8_t address[16];
        uint16_t port = 0;
        bool native_agent = !q->datagram &&
                            wendy_net_peer_agent_endpoint_now(q->peer, address, &port) == ESP_OK &&
                            port == q->port;
        esp_err_t endpoint =
            native_agent ? ESP_OK : wendy_net_peer_app_endpoint_now(q->peer, address, &port);
        if (endpoint != ESP_OK && esp_timer_get_time() < q->deadline) {
            pthread_mutex_lock(&request_lock);
            if (atomic_load(&ready) && !pending_guest) {
                pending_guest = q;
                q = NULL;
            }
            pthread_mutex_unlock(&request_lock);
        }
        if (q) {
            struct app_flow *f = endpoint == ESP_OK ? new_flow(-1, true) : NULL;
            if (f && endpoint == ESP_OK) {
                char host[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, address, host, sizeof host);
                f->fd = wnad_connect(host, port, &f->connecting);
        }
            if (f && f->fd >= 0) {
                f->guest_handle = q->handle;
                f->service_port = q->port;
                memcpy(f->expected, q->peer, 37);
                f->native_agent = native_agent;
                if (q->datagram)
                    f->datagram_max = (uint16_t)wendy_net_guest_datagram_capacity();
                memcpy(f->request, q->datagram ? "WAU3" : "WAS1", 4);
                wn_put16(f->request + 4, q->port);
                wn_put16(f->request + 6, f->datagram_max);
            app_actor_add(f);
            } else {
                if (f)
                    close_flow(f);
                else
                    atomic_fetch_sub(&outbound_flows, 1);
                wendy_net_mesh_connected(q->handle, -1);
            }
            wendy_net_free(q);
            progress = 1;
        }
    }
#endif
    for (struct datagram_flow **at = &datagram_flows; *at;) {
        struct datagram_flow *d = *at;
        /* Raw binding and upper control share a retained session. A preceding
         * flow may advance its clock during negotiation; never pass an older
         * loop-wide snapshot to the next owner's monotonic session check. */
        int r = d->flow.disposing ? -1 : app_step(&d->flow, esp_timer_get_time());
        struct datagram_flow *next = d->next;
        if (r < 0 && dispose_flow(&d->flow)) {
            *at = next;
            progress = 1;
        } else {
            progress |= r > 0;
            at = &d->next;
        }
    }
    progress |= schedule_promoted_raw();
    return progress;
}
bool wendy_net_app_stop(void)
{
    atomic_store(&ready, false);
    int fd = atomic_exchange(&listener, -1);
    if (fd >= 0)
        close(fd);
#if CONFIG_WENDY_NET
    wendy_net_set_mesh_waker(NULL);
    wendy_net_set_mesh_connector(NULL);
    wendy_net_set_mesh_resolver(NULL);
    wendy_net_set_service_catalog(NULL);
    pthread_mutex_lock(&request_lock);
    struct guest_connect *q = pending_guest;
    pending_guest = NULL;
    pthread_mutex_unlock(&request_lock);
    if (q) {
        wendy_net_mesh_connected(q->handle, -1);
        atomic_fetch_sub(&outbound_flows, 1);
        wendy_net_free(q);
    }
#endif
    for (struct datagram_flow **at = &datagram_flows; *at;) {
        struct app_flow *f = &(*at)->flow;
        f->state.cancel = true;
        struct datagram_flow *next = (*at)->next;
        if (dispose_flow(f))
            *at = next;
        else
            at = &(*at)->next;
    }
    bool done = datagram_flows == NULL;
#if CONFIG_WENDY_NET
    if (done)
        wendy_net_mesh_discard_pending_datagrams();
#endif
    if (done)
        atomic_store(&starting, false);
    return done;
}
void wendy_net_app_watch(fd_set *rd, fd_set *wr, int *maximum, int64_t *deadline)
{
#if CONFIG_WENDY_NET
    pthread_mutex_lock(&request_lock);
    if (pending_guest) {
        int64_t next = esp_timer_get_time() + INT64_C(1000000);
        if (pending_guest->deadline < next)
            next = pending_guest->deadline;
        if (next < *deadline)
            *deadline = next;
    }
    pthread_mutex_unlock(&request_lock);
#endif
    int fd = atomic_load(&listener);
    if (fd >= 0 && incoming_admission_ready()) {
        FD_SET(fd, rd);
        if (fd > *maximum)
            *maximum = fd;
    }
    for (struct datagram_flow *d = datagram_flows; d; d = d->next) {
        struct app_flow *f = &d->flow;
        if (f->state.lent || f->disposing)
            continue;
        /* Preserve one immediate retry across the outer actor's work quota.
         * app_step clears this before polling, so WANT_READ/WRITE cannot spin. */
        if (f->local_progress)
            *deadline = esp_timer_get_time();
        if (f->outbound && f->negotiated && f->direct_control && f->direct_control->peer) {
            struct app_control *c = f->direct_control;
            if (c->next_raw_attempt > esp_timer_get_time() && c->next_raw_attempt < *deadline)
                *deadline = c->next_raw_attempt;
        }
        if (f->direct_raw && f->direct_raw->retiring && f->direct_raw->drain_deadline < *deadline)
            *deadline = f->direct_raw->drain_deadline;
        if (!f->negotiated && (int64_t)f->state.deadline < *deadline)
            *deadline = (int64_t)f->state.deadline;
        if (f->state.retry_at && f->state.retry_at > (uint64_t)esp_timer_get_time() &&
            f->state.retry_at < (uint64_t)*deadline)
            *deadline = (int64_t)f->state.retry_at;
        bool can_read =
            !f->negotiated || f->direct_control || f->datagram_max ||
            (f->buffers && f->buffers[0].offset == f->buffers[0].size && !f->buffers[0].eof);
        if (can_read && f->state.phase == WNA_READY &&
           (f->channel.input.size || (f->connection && wendy_pki_pending(f->connection))))
            *deadline = esp_timer_get_time();
        fd = f->fd;
        if (fd >= 0) {
            if (wna_buffer_space(&f->channel.input))
                FD_SET(fd, rd);
            if (f->connecting || f->channel.output.size)
                FD_SET(fd, wr);
            if (fd > *maximum)
                *maximum = fd;
        }
        if (f->backend >= 0) {
            fd = f->backend;
            if (f->backend_connecting)
                FD_SET(fd, wr);
            else if (f->buffers) {
                if (f->buffers[1].offset == f->buffers[1].size && !f->buffers[1].eof)
                    FD_SET(fd, rd);
                if (f->buffers[0].offset < f->buffers[0].size)
                    FD_SET(fd, wr);
            }
            if (fd > *maximum)
                *maximum = fd;
        }
        if (f->pair_listener >= 0) {
            FD_SET(f->pair_listener, rd);
            if (f->pair_listener > *maximum)
                *maximum = f->pair_listener;
        }
    }
}
esp_err_t wendy_net_app_start(void)
{
    if (atomic_exchange(&starting, true))
        return ESP_OK;
    int fd = socket(AF_INET6, SOCK_STREAM, 0), yes = 1, v6_only = 0;
    struct sockaddr_in6 addr = {.sin6_family = AF_INET6, .sin6_port = htons(APP_PORT)};
    if (fd < 0)
        goto failed;
    if (fd >= FD_SETSIZE || setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes) ||
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6_only, sizeof v6_only) ||
        bind(fd, (struct sockaddr *)&addr, sizeof addr) ||
        listen(fd, CONFIG_WENDY_NET_APP_MAX_FLOWS) || fcntl(fd, F_SETFL, O_NONBLOCK) < 0)
        goto failed;
    atomic_store(&listener, fd);
    atomic_store(&ready, true);
#if CONFIG_WENDY_NET
    wendy_net_set_mesh_waker(wnad_wake);
    wendy_net_set_mesh_connector(guest_mesh_begin);
    wendy_net_set_mesh_resolver(guest_mesh_resolve);
    wendy_net_set_service_catalog(wendy_net_peer_service_catalog);
#endif
    ESP_LOGI(TAG, "TLS app listener ready on TCP%u; per-direction flow cap=%u", APP_PORT,
             (unsigned)CONFIG_WENDY_NET_APP_MAX_FLOWS);
    return ESP_OK;
failed:
    if (fd >= 0)
        close(fd);
    atomic_store(&starting, false);
    return ESP_FAIL;
}
/* Keep the bounded TCP backlog while all relay slots are occupied. Accepting
 * and closing immediately would turn an ordinary reconnect into a TLS EOF. */
int wendy_net_app_listener(void)
{
    return -1; /* The mesh actor owns VIP acceptance, not the management worker. */
}
bool wendy_net_app_management_ready(void)
{
    if (!wendy_pki_handshake_available())
        return false;
#if CONFIG_WENDY_NET_MANAGEMENT_SETUP_FREE_BYTES > 0
    unsigned flows = atomic_load(&inbound_flows) + atomic_load(&outbound_flows);
    bool bulk = flows != 0;
    size_t available = heap_caps_get_free_size(MALLOC_CAP_8BIT);
#if CONFIG_WENDY_NET_RETAIN_TLS_INPUT
    available += wendy_pki_input_workspace_cached_bytes();
#endif
    return !bulk || available >= CONFIG_WENDY_NET_MANAGEMENT_SETUP_FREE_BYTES;
#else
    return true;
#endif
}
bool wendy_net_app_ready(void)
{
    return atomic_load(&ready);
}
