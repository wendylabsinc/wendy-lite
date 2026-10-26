#include "wendy_mesh.h"
#include "wendy_mesh_discovery.h"
#include "wendy_wifi.h"
#include "wendy_mesh_status.h"
#include "wendy_mesh_uplink.h"
#if CONFIG_WENDY_MESH_CLOUD_UPLINK
#include "wendy_cloud.h"
#include "lwip/dns.h"
#include "lwip/ip4.h"
#endif
#include "wendy_mesh_connect.h"
#include "wendy_mesh_directory.h"
#include "wendy_conf.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "lwip/netif.h"
#include "lwip/tcpip.h"
#include "lwip/priv/tcpip_priv.h"
#include "lwip/ip6.h"
#include "lwip/sockets.h"
#include <mbedtls/base64.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MESH_STACK_BYTES 32768
#define MESH_QUEUE_PACKETS 4
struct queued_packet
{
    uint16_t size;
    uint8_t data[WENDY_MESH_MTU];
};
struct mesh_state
{
    char peer[37]; // authenticated peer, protected by state_lock for UI snapshots
    char active_carrier[16]; // protected by state_lock
    struct wm_directory directory;
    struct wm_epoch epoch;
    struct wm_identity_requests identity_requests;
    struct wm_assembler assembler;
    struct netif netif;
    struct wendy_pki_mesh_identity identity;
    wendy_pki_connection* connection;
    struct wm_carrier carrier;
    QueueHandle_t queue;
    StaticQueue_t queue_control;
    uint8_t queue_storage[MESH_QUEUE_PACKETS * sizeof(struct queued_packet)];
    char control[WENDY_MESH_CONTROL_MAX + 1];
    uint8_t certificate_scratch[32768];
    struct wendy_pki_mesh_peer certificate_peer; /* ML-DSA-65 keys are too large for the stack. */
    uint8_t own_address[16], device[16];
    uint64_t revision, router_id;
    uint16_t seqno, hello_seq;
    uint32_t packet_id;
    int64_t own_deadline_us;
    int64_t certificate_expires; /* Snapshot copy protected by state_lock. */
    bool interface_added;
    atomic_bool active;
#if CONFIG_WENDY_MESH_CLOUD_UPLINK
    struct netif uplink_netif;
    struct netif* direct_netif;
    ip_addr_t previous_dns[DNS_MAX_SERVERS], gateway_dns;
    uint8_t gateway[16], lease[4];
    int64_t uplink_deadline;
    atomic_bool uplink_active, uplink_workers_ready;
    atomic_uint generation, direct_successes;
    bool uplink_added;
#endif
};
/* Protocol storage has a compile-time cap, including the certificate decode
 * workspace and an ML-DSA-65 key slot for each origin. TLS/X.509 allocations
 * are separately bounded by input limits. The state lives in PSRAM. */
_Static_assert(sizeof(struct mesh_state) < 192 * 1024, "mesh protocol storage exceeds 192 KiB");
static _Atomic(struct mesh_state*) state;
static pthread_mutex_t state_lock = PTHREAD_MUTEX_INITIALIZER;
static TaskHandle_t mesh_task_handle;
static const char* TAG = "wendy_mesh";
static enum wendy_mesh_phase phase = WENDY_MESH_UNAVAILABLE;

static void publish_phase(enum wendy_mesh_phase next)
{
    pthread_mutex_lock(&state_lock);
    phase = next;
    pthread_mutex_unlock(&state_lock);
}

void wendy_mesh_get_snapshot(struct wendy_mesh_snapshot* out)
{
    if (!out) return;
    memset(out, 0, sizeof *out);
#if CONFIG_WENDY_MESH_WIFI_BLE
    snprintf(out->carrier, sizeof out->carrier, "Wi-Fi/BLE");
#elif CONFIG_WENDY_MESH_TCP
    snprintf(out->carrier, sizeof out->carrier, "Wi-Fi TCP");
#elif CONFIG_WENDY_MESH_BLE
    snprintf(out->carrier, sizeof out->carrier, "BLE");
#else
    snprintf(out->carrier, sizeof out->carrier, "ESP-NOW");
#endif

#if !CONFIG_WENDY_MESH_AUTO_DISCOVER && !CONFIG_WENDY_MESH_WIFI_BLE
    uint8_t peer_uuid[16];
    if (wm_uuid_parse(CONFIG_WENDY_MESH_ROUTER_DEVICE, peer_uuid)
#if CONFIG_WENDY_MESH_TCP
        || !CONFIG_WENDY_MESH_ROUTER_HOST[0]
#endif
    ) {
        out->phase = WENDY_MESH_PEER_REQUIRED;
        return;
    }
    wm_uuid_format(peer_uuid, out->peer);
#endif
    pthread_mutex_lock(&state_lock);
    struct mesh_state* s = state;
    out->phase = phase;
    if (s) {
        if (s->active_carrier[0])
            memcpy(out->carrier, s->active_carrier, sizeof out->carrier);
        memcpy(out->peer, s->peer, sizeof out->peer);
        int64_t now = esp_timer_get_time();
        if (wendy_conf_is_current() && !wendy_pki_reset_in_progress()) {
            memcpy(out->device, s->epoch.device, sizeof out->device);
            out->peer_connected = (phase == WENDY_MESH_QUARANTINE || phase == WENDY_MESH_ONLINE)
                && now >= s->epoch.clock_monotonic_us
                && now - s->epoch.clock_monotonic_us < WENDY_MESH_TIME_MAX_AGE_US
                && s->own_deadline_us > now
                && wm_epoch_time(&s->epoch, now) > 0
                && wm_epoch_time(&s->epoch, now) / 1000 < s->certificate_expires;
            if (out->peer_connected) {
                out->ip_active = atomic_load(&s->active) && wm_epoch_ready(&s->epoch, now);
                if (!wm_epoch_ready(&s->epoch, now))
                    out->quarantine_seconds = (uint32_t)((s->epoch.ready_after_us - now - 1) / 1000000 + 1);
                out->member_count = wm_directory_members(&s->directory, now,
                    out->members, WENDY_MESH_ORIGINS_MAX);
            } else if (phase == WENDY_MESH_ONLINE || phase == WENDY_MESH_QUARANTINE) {
                out->phase = WENDY_MESH_RETRYING;
            }
        } else {
            out->phase = WENDY_MESH_WAITING_ENROLLMENT;
        }
    }
    pthread_mutex_unlock(&state_lock);
}

static bool identity_live(struct mesh_state* s, int64_t now)
{
    return wendy_conf_is_current() && !wendy_pki_reset_in_progress()
        && now >= s->identity.verified_monotonic_us
        && now - s->identity.verified_monotonic_us < WENDY_MESH_TIME_MAX_AGE_US
        && wm_epoch_time(&s->epoch, now) > 0
        && wm_epoch_time(&s->epoch, now) / 1000 < s->identity.certificate_expires;
}
static int64_t signed_now(struct mesh_state* s, int64_t now)
{
    return wm_epoch_time(&s->epoch, now);
}
static bool ip_profile(const uint8_t* p, size_t n)
{
    return wm_ip_valid(p, n) && (p[6] == 6 || p[6] == 17 || p[6] == 58
#if CONFIG_WENDY_MESH_CLOUD_UPLINK
        || (p[6] == 4 && wm_uplink_ip4(p + 40, n - 40))
#endif
    );
}
/* ESP-IDF reserves netif->state for esp_netif_t. These raw lwIP interfaces
 * leave it NULL so global link/address callbacks do not interpret mesh state
 * as an ESP-NETIF object. Output callbacks use the published singleton. */
static err_t output_ip6(struct netif* netif, struct pbuf* p, const ip6_addr_t* destination)
{
    (void)destination;
    struct mesh_state* s = state;
    struct queued_packet packet;
    if (!s || netif != &s->netif) return ERR_IF;
    if (!atomic_load(&s->active) || p->tot_len > sizeof packet.data || p->tot_len < 40)
        return ERR_RTE;
    packet.size = p->tot_len;
    if (pbuf_copy_partial(p, packet.data, packet.size, 0) != packet.size
        || !ip_profile(packet.data, packet.size) || memcmp(packet.data + 8, s->own_address, 16))
        return ERR_RTE;
    int64_t now = esp_timer_get_time();
    pthread_mutex_lock(&state_lock);
    bool allowed = identity_live(s, now) && s->own_deadline_us > now
        && wm_directory_address(&s->directory, packet.data + 24, now);
    pthread_mutex_unlock(&state_lock);
    return allowed && xQueueSend(s->queue, &packet, 0) == pdTRUE ? ERR_OK : ERR_RTE;
}
#if CONFIG_WENDY_MESH_CLOUD_UPLINK
static err_t uplink_output(struct netif* netif, struct pbuf* p, const ip4_addr_t* destination)
{
    (void)destination;
    struct mesh_state* s = state;
    struct queued_packet packet;
    if (!s || netif != &s->uplink_netif) return ERR_IF;
    if (!atomic_load(&s->active) || !atomic_load(&s->uplink_active)
        || p->tot_len > 1280 || pbuf_copy_partial(p, packet.data + 40, p->tot_len, 0) != p->tot_len)
        return ERR_RTE;
    int64_t now = esp_timer_get_time();
    pthread_mutex_lock(&state_lock);
    bool allowed = identity_live(s, now) && s->own_deadline_us > now
        && s->uplink_deadline > now && wm_directory_address(&s->directory, s->gateway, now);
    packet.size = allowed ? wm_uplink_wrap(packet.data, s->own_address, s->gateway,
        s->lease, packet.data + 40, p->tot_len) : 0;
    pthread_mutex_unlock(&state_lock);
    return packet.size && xQueueSend(s->queue, &packet, 0) == pdTRUE ? ERR_OK : ERR_RTE;
}
static err_t uplink_netif_init(struct netif* netif)
{
    netif->name[0] = 'w'; netif->name[1] = 'u';
    netif->mtu = 1280;
    netif->output = uplink_output;
    return ERR_OK;
}
/* Called only on lwIP's core thread. Preserve DHCP changes made while we own
 * the default, and restore only DNS entries which still contain our value. */
static void uplink_down(struct mesh_state* s)
{
    atomic_store(&s->uplink_active, false);
    if (!s->uplink_added) return;
    if (netif_default == &s->uplink_netif) netif_set_default(s->direct_netif);
    for (unsigned i = 0; i < DNS_MAX_SERVERS; i++)
        if (ip_addr_cmp(dns_getserver(i), &s->gateway_dns))
            dns_setserver(i, &s->previous_dns[i]);
    netif_set_down(&s->uplink_netif);
    netif_set_link_down(&s->uplink_netif);
}
#endif
static err_t mesh_netif_init(struct netif* netif)
{
    netif->name[0] = 'w';
    netif->name[1] = 'm';
    netif->mtu = WENDY_MESH_MTU;
    netif->output_ip6 = output_ip6;
    netif->flags = 0;
    return ERR_OK;
}
struct netif_change
{
    struct tcpip_api_call_data call;
    struct mesh_state* s;
    bool up;
};
static err_t change_netif(struct tcpip_api_call_data* data)
{
    struct netif_change* change = (struct netif_change*)data;
    struct mesh_state* s = change->s;
    if (change->up)
    {
        if (!s->interface_added)
        {
            if (!netif_add_noaddr(&s->netif, NULL, mesh_netif_init, tcpip_input))
                return ERR_IF;
            s->interface_added = true;
        }
        ip6_addr_t address;
        memset(&address, 0, sizeof address);
        memcpy(address.addr, s->own_address, 16);
        netif_ip6_addr_set(&s->netif, 0, &address);
        netif_ip6_addr_set_state(&s->netif, 0, IP6_ADDR_PREFERRED);
        netif_set_link_up(&s->netif);
        netif_set_up(&s->netif);
    }
    else if (s->interface_added)
    {
#if CONFIG_WENDY_MESH_CLOUD_UPLINK
        uplink_down(s);
#endif
        netif_set_down(&s->netif);
        netif_set_link_down(&s->netif);
        netif_ip6_addr_set_state(&s->netif, 0, IP6_ADDR_INVALID);
    }
    return ERR_OK;
}
/* Only the mesh /48 uses this point-to-point interface; ordinary Wi-Fi routing
 * remains under ESP-IDF. Output additionally requires an active signed /128. */
struct netif* lwip_hook_ip6_route(const ip6_addr_t* source, const ip6_addr_t* destination)
{
    (void)source;
    static const uint8_t prefix[] = { 0xfd, 0x45, 0xb8, 0x91, 0x56, 0x7f };
    struct mesh_state* s = state;
    return s && atomic_load(&s->active) && !memcmp(destination->addr, prefix, sizeof prefix)
        ? &s->netif
        : NULL;
}
static int wait_io(struct mesh_state* s, bool writing, int64_t deadline)
{
    int64_t now = esp_timer_get_time();
    if (!identity_live(s, now) || now >= deadline)
        return -1;
    int64_t slice = now + 200000;
    return wendy_pki_wait(s->connection, writing, deadline < slice ? deadline : slice) < 0 ? -1 : 0;
}
static int transfer(struct mesh_state* s, void* buffer, size_t size, bool writing)
{
    uint8_t* p = buffer;
    int64_t deadline = esp_timer_get_time() + INT64_C(30000000);
    while (size)
    {
        int64_t now = esp_timer_get_time();
        if (!identity_live(s, now) || now >= deadline)
            return -1;
        ssize_t n = writing ? wendy_pki_write(s->connection, p, size)
                            : wendy_pki_read(s->connection, p, size);
        if (n > 0)
        {
            p += n;
            size -= n;
            continue;
        }
        if (n != -2 && n != -3)
            return -1;
        if (wait_io(s, n == -3, deadline))
            return -1;
    }
    return 0;
}
static int write_control(struct mesh_state* s, const char* json, size_t size, bool bootstrap)
{
    if (!size || size > WENDY_MESH_CONTROL_MAX)
        return -1;
    uint8_t header[9];
    size_t length;
    if (bootstrap)
    {
        wm_put32(header, size);
        length = 4;
    }
    else
    {
        header[0] = 1;
        wm_put32(header + 1, size + 4);
        wm_put32(header + 5, size);
        length = 9;
    }
    return transfer(s, header, length, true) || transfer(s, (void*)json, size, true) ? -1 : 0;
}
static int write_packet(struct mesh_state* s, const uint8_t* data, size_t size)
{
    if (!size || size > WENDY_MESH_DATAGRAM)
        return -1;
    uint8_t header[5] = { 2 };
    wm_put32(header + 1, size);
    return transfer(s, header, sizeof header, true) || transfer(s, (void*)data, size, true) ? -1
                                                                                            : 0;
}
static int send_bundle(struct mesh_state* s)
{
    const char prefix[] = "{\"kind\":\"bundle\",\"bundle\":";
    size_t start = sizeof prefix - 1;
    memcpy(s->control, prefix, start);
    int n = wendy_pki_mesh_bundle(s->connection, s->control + start, sizeof s->control - start - 1);
    if (n < 0)
        return -1;
    s->control[start + n] = '}';
    return write_control(s, s->control, start + n + 1, false);
}
static int announce(struct mesh_state* s, bool renew)
{
    int64_t now_us = esp_timer_get_time(), now = signed_now(s, now_us);
    if (!identity_live(s, now_us))
        return -1;
    if (renew)
    {
        if (s->revision >= s->identity.revision_limit)
            return -1;
        struct wm_manifest manifest = { .revision = s->revision++,
            .router_id = s->router_id,
            .seqno = ++s->seqno,
            .issued = now,
            .expires = now + WENDY_MESH_LEASE_SECONDS * 1000,
            .agent_port = 5054 };
        if (manifest.expires > (int64_t)s->identity.certificate_expires * 1000)
            manifest.expires = (int64_t)s->identity.certificate_expires * 1000;
        if (manifest.expires <= now + 5000)
            return -1;
        memcpy(manifest.device, s->device, 16);
        char body[768], principal[106], signature64[113];
        uint8_t signature[80];
        size_t sigsize = 0, encoded = 0;
        int n = wm_manifest_write(&manifest, body, sizeof body);
        if (n < 0 || wm_principal(s->identity.tenant, s->identity.device, principal) < 0
            || wendy_pki_mesh_sign(s->connection, principal, body, n, signature, &sigsize)
            || mbedtls_base64_encode(
                (unsigned char*)signature64, sizeof signature64, &encoded, signature, sigsize))
            return -1;
        n = snprintf(s->control, sizeof s->control,
            "{\"kind\":\"manifest\",\"manifest\":{\"principal\":\"%s\",\"body\":%s,\"signature\":"
            "\"%s\"}}",
            principal, body, signature64);
        if (n < 0 || (size_t)n >= sizeof s->control || write_control(s, s->control, n, false))
            return -1;
        pthread_mutex_lock(&state_lock);
        s->own_deadline_us = now_us + (manifest.expires - now) * INT64_C(1000);
        pthread_mutex_unlock(&state_lock);
    }
    uint8_t packet[65] = { 2 };
    size_t size = wm_babel_announce(packet + 1, s->device, s->router_id, s->seqno, ++s->hello_seq);
    return size ? write_packet(s, packet, size + 1) : -1;
}
static int receive_control(struct mesh_state* s, size_t size)
{
    struct wm_json doc;
    if (wm_json_parse(&doc, s->control, size))
        return -1;
    int kind = wm_json_member(&doc, 0, "kind");
    int64_t now_us = esp_timer_get_time();
    if (wm_json_equal(&doc, kind, "bundle"))
    {
        static const char* const fields[] = { "kind", "bundle", NULL };
        int bundle = wm_json_member(&doc, 0, "bundle");
        if (!wm_json_fields(&doc, 0, fields) || bundle < 0 || doc.tokens[bundle].type != '[')
            return -1;
        const uint8_t* der[8];
        size_t sizes[8], total = 0, count = 0;
        for (unsigned i = bundle + 1; i < doc.tokens[bundle].next; i = doc.tokens[i].next)
        {
            const struct wm_token* t = &doc.tokens[i];
            if (count == 8 || t->type != '"')
                return -1;
            if (mbedtls_base64_decode(s->certificate_scratch + total,
                    sizeof s->certificate_scratch - total, &sizes[count],
                    (const unsigned char*)doc.text + t->start + 1, t->end - t->start - 2))
                return -1;
            der[count] = s->certificate_scratch + total;
            total += sizes[count++];
        }
        struct wendy_pki_mesh_peer* peer = &s->certificate_peer;
        if (wendy_pki_mesh_verify_bundle(
                s->connection, der, sizes, count, signed_now(s, now_us) / 1000, peer))
            return -1;
        if (!strcmp(peer->device, s->identity.device))
            return 0;
        uint8_t peer_uuid[16], peer_address[16];
        if (wm_uuid_parse(peer->device, peer_uuid))
            return -1;
        wm_address(peer_uuid, peer_address);
        if (!memcmp(peer_address, s->own_address, 16))
            return -1;
        pthread_mutex_lock(&state_lock);
        int result = wm_directory_add(&s->directory, peer);
        pthread_mutex_unlock(&state_lock);
        /* Full cache is a resource refusal, never an eviction of replay state. */
        return result < 0 ? -1 : 0;
    }
    if (wm_json_equal(&doc, kind, "manifest"))
    {
        static const char* const fields[] = { "kind", "manifest", NULL };
        int manifest = wm_json_member(&doc, 0, "manifest");
        if (!wm_json_fields(&doc, 0, fields) || manifest < 0)
            return -1;
        pthread_mutex_lock(&state_lock);
        int result = wm_directory_apply(
            &s->directory, s->identity.tenant, &doc, manifest, signed_now(s, now_us), now_us);
        pthread_mutex_unlock(&state_lock);
        if (result == WM_DIRECTORY_IDENTITY_NEEDED)
        {
            /* Routers remember completed bundle writes across reconnects, but
             * this leaf's identity cache is lost on reboot. Ask for the missing
             * chain; a later reconciled proof still needs full verification. */
            char principal[106], request[160];
            uint8_t device[16];
            if (wm_json_string(&doc, wm_json_member(&doc, manifest, "principal"),
                    principal, sizeof principal) < 0
                || wm_principal_device(principal, s->identity.tenant, device))
                return -1;
            if (!memcmp(device, s->device, 16) || s->directory.count == WENDY_MESH_ORIGINS_MAX
                || !wm_identity_request_due(&s->identity_requests, device, now_us))
                return 0;
            int n = snprintf(request, sizeof request,
                "{\"kind\":\"identity-request\",\"principal\":\"%s\"}", principal);
            return n > 0 && (size_t)n < sizeof request
                ? write_control(s, request, n, false) : -1;
        }
        return result < 0 ? -1 : 0;
    }
    if (wm_json_equal(&doc, kind, "identity-request"))
    {
        static const char* const fields[] = { "kind", "principal", NULL };
        char principal[106];
        if (!wm_json_fields(&doc, 0, fields)
            || wm_principal(s->identity.tenant, s->identity.device, principal) < 0
            || !wm_json_equal(&doc, wm_json_member(&doc, 0, "principal"), principal))
            return -1;
        return send_bundle(s) || announce(s, true) ? -1 : 0;
    }
    return -1;
}
static int receive_frame(struct mesh_state* s, uint8_t first)
{
    uint8_t header[5] = { first };
    if (transfer(s, header + 1, sizeof header - 1, false))
        return -1;
    size_t size = wm_get32(header + 1);
    if (header[0] == 1)
    {
        uint8_t inner[4];
        if (size < 5 || size > WENDY_MESH_CONTROL_MAX + 4 || transfer(s, inner, 4, false)
            || wm_get32(inner) != size - 4)
            return -1;
        size -= 4;
        if (transfer(s, s->control, size, false))
            return -1;
        s->control[size] = 0;
        return receive_control(s, size);
    }
    if (header[0] != 2 || !size || size > WENDY_MESH_DATAGRAM)
        return -1;
    uint8_t packet[WENDY_MESH_DATAGRAM];
    if (transfer(s, packet, size, false))
        return -1;
    if (packet[0] == 2)
    {
        /* The leaf has one next hop and does not install or re-advertise
         * learned routes. Periodic own proofs/updates answer route requests. */
        return size >= 5 && packet[1] == 42 && packet[2] == 2 && wm_get16(packet + 3) <= size - 5
            ? 0
            : -1;
    }
    int64_t now = esp_timer_get_time();
    int assembled = wm_assemble(&s->assembler, packet, size, now);
    if (assembled < 0)
        return -1;
    if (!assembled)
        return 0;
    uint8_t* ip = s->assembler.packet;
    if (!ip_profile(ip, assembled) || memcmp(ip + 24, s->own_address, 16))
        return -1;
    pthread_mutex_lock(&state_lock);
    bool allowed = identity_live(s, now) && s->own_deadline_us > now
        && wm_directory_address(&s->directory, ip + 8, now);
    pthread_mutex_unlock(&state_lock);
    if (!atomic_load(&s->active) || !wm_epoch_ready(&s->epoch, now))
        return 0;
    /* Proofs can expire or arrive after IP during cache repair. Drop the
     * unauthorized packet without destroying the authenticated carrier. */
    if (!allowed)
        return 0;
    struct netif* input_netif = &s->netif;
#if CONFIG_WENDY_MESH_CLOUD_UPLINK
    if (ip[6] == 4) {
        pthread_mutex_lock(&state_lock);
        bool valid = atomic_load(&s->uplink_active) && s->uplink_deadline > now
            && wm_uplink_unwrap(s->own_address, s->gateway, s->lease, ip, assembled);
        pthread_mutex_unlock(&state_lock);
        if (!valid) return 0;
        ip += 40; assembled -= 40;
        input_netif = &s->uplink_netif;
    }
#endif
    struct pbuf* p = pbuf_alloc(PBUF_RAW, assembled, PBUF_RAM);
    if (!p)
        return -1;
    if (pbuf_take(p, ip, assembled) != ERR_OK || tcpip_input(p, input_netif) != ERR_OK)
    {
        pbuf_free(p);
        return -1;
    }
    return 0;
}
static int session(struct mesh_state* s)
{
    struct wm_mesh_connection attempt = { 0 };
    int result = wm_mesh_connect(&attempt, publish_phase);
    s->connection = attempt.connection;
    s->identity = attempt.identity;
    s->carrier = attempt.carrier;
    if (result) return -1;
    const char* peer = s->identity.peer;
    pthread_mutex_lock(&state_lock);
    memcpy(s->peer, peer, sizeof s->peer);
    snprintf(s->active_carrier, sizeof s->active_carrier, "%s", s->carrier.name);
    pthread_mutex_unlock(&state_lock);
    ESP_LOGI(TAG, "mesh peer %s authenticated over %s", peer, s->carrier.name);
    if (wm_uuid_parse(s->identity.device, s->device))
        return -1;
    pthread_mutex_lock(&state_lock);
    int bound = wm_directory_bind(&s->directory, &s->epoch, &s->identity);
    s->certificate_expires = s->identity.certificate_expires;
    pthread_mutex_unlock(&state_lock);
    if (bound)
        return -1;
    wm_address(s->device, s->own_address);
    s->revision = s->identity.revision_first;
    s->seqno = 0;
    s->hello_seq = 0;
    do
    {
        esp_fill_random(&s->router_id, sizeof s->router_id);
    } while (!s->router_id || s->router_id == UINT64_MAX);
    int size = wm_hello_write(
        s->identity.device, peer, s->control, sizeof s->control);
    if (size < 0 || write_control(s, s->control, size, true))
        return -1;
    uint8_t header[4];
    if (transfer(s, header, 4, false))
        return -1;
    size = wm_get32(header);
    if (size < 1 || size > 512 || transfer(s, s->control, size, false)
        || wm_hello_check(s->control, size, s->identity.device, peer))
        return -1;
    if (send_bundle(s) || announce(s, true))
        return -1;
    publish_phase(WENDY_MESH_QUARANTINE);
    int64_t renewed = esp_timer_get_time(), announced = renewed;
    ESP_LOGI(TAG,
        "authenticated mesh leaf; waiting for cold-boot replay barrier; storage=%u stack=%u free "
        "heap=%u",
        (unsigned)sizeof *s, MESH_STACK_BYTES, (unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT));
    while (identity_live(s, esp_timer_get_time()))
    {
        int64_t now = esp_timer_get_time();
        if (!atomic_load(&s->active) && wm_epoch_ready(&s->epoch, now))
        {
            struct netif_change change = { .s = s, .up = true };
            if (tcpip_api_call(change_netif, &change.call) != ERR_OK)
                return -1;
#if CONFIG_WENDY_MESH_CLOUD_UPLINK
            atomic_fetch_add(&s->generation, 1);
#endif
            atomic_store(&s->active, true);
            publish_phase(WENDY_MESH_ONLINE);
            ESP_LOGI(TAG, "mesh leaf IP active after replay barrier");
        }
        if (now - renewed >= WENDY_MESH_RENEW_SECONDS * INT64_C(1000000))
        {
            if (announce(s, true))
                return -1;
            renewed = announced = now;
        }
        else if (now - announced >= INT64_C(4000000))
        {
            if (announce(s, false))
                return -1;
            announced = now;
        }
        struct queued_packet queued;
        if (xQueueReceive(s->queue, &queued, 0) == pdTRUE)
        {
            pthread_mutex_lock(&state_lock);
            bool live = wm_directory_address(&s->directory, queued.data + 24, now)
                && s->own_deadline_us > now;
#if CONFIG_WENDY_MESH_CLOUD_UPLINK
            if (queued.data[6] == 4)
                live = live && atomic_load(&s->uplink_active) && s->uplink_deadline > now
                    && !memcmp(queued.data + 24, s->gateway, 16)
                    && !memcmp(queued.data + 52, s->lease, 4);
#endif
            pthread_mutex_unlock(&state_lock);
            if (live)
                for (size_t offset = 0; offset < queued.size; offset += 1091)
                {
                    uint8_t fragment[WENDY_MESH_DATAGRAM];
                    size_t n
                        = wm_fragment(fragment, queued.data, queued.size, s->packet_id, offset);
                    if (!n || write_packet(s, fragment, n))
                        return -1;
                }
            s->packet_id++;
        }
        /* Nonblocking first-byte read works for sockets and radio streams.
         * A wakeup can be spurious; it must not start a frame timeout. */
        uint8_t first;
        ssize_t got = wendy_pki_read(s->connection, &first, 1);
        if (got == 1) {
            if (receive_frame(s, first)) return -1;
        } else if (got == -2 || got == -3) {
            if (wendy_pki_wait(s->connection, got == -3, esp_timer_get_time() + 20000) < 0)
                return -1;
        } else return -1;
    }
    return -1;
}
#if CONFIG_WENDY_MESH_CLOUD_UPLINK
struct uplink_change {
    struct tcpip_api_call_data call;
    struct mesh_state* s;
    unsigned action, generation;
    uint8_t lease[4];
    int64_t deadline;
    char direct_name[16], direct_dns[48];
};
static err_t change_uplink(struct tcpip_api_call_data* data)
{
    struct uplink_change* c = (struct uplink_change*)data;
    struct mesh_state* s = c->s;
    if (c->action == 0) { uplink_down(s); return ERR_OK; }
    if (c->action == 2) {
        struct netif* direct = s->direct_netif;
        if (netif_default && netif_default != &s->uplink_netif && netif_default != &s->netif)
            direct = netif_default;
        if (direct && netif_is_up(direct) && netif_is_link_up(direct)
            && !ip4_addr_isany_val(*netif_ip4_addr(direct)))
            netif_index_to_name(netif_get_index(direct), c->direct_name);
        for (unsigned i = 0; i < DNS_MAX_SERVERS && !c->direct_dns[0]; i++) {
            const ip_addr_t* dns = dns_getserver(i);
            if (ip_addr_cmp(dns, &s->gateway_dns)) dns = &s->previous_dns[i];
            if (!ip_addr_isany(dns)) ipaddr_ntoa_r(dns, c->direct_dns, sizeof c->direct_dns);
        }
        return ERR_OK;
    }
    if (c->action == 3) {
        if (!atomic_load(&s->uplink_active)) return ERR_RTE;
        if (netif_default != &s->uplink_netif) s->direct_netif = netif_default;
        for (unsigned i = 0; i < DNS_MAX_SERVERS; i++) {
            if (!ip_addr_cmp(dns_getserver(i), &s->gateway_dns))
                s->previous_dns[i] = *dns_getserver(i);
            dns_setserver(i, &s->gateway_dns);
        }
        netif_set_default(&s->uplink_netif);
        return ERR_OK;
    }
    if (!atomic_load(&s->active) || atomic_load(&s->generation) != c->generation
        || c->deadline <= esp_timer_get_time()) return ERR_RTE;
    if (!s->uplink_added) {
        if (!netif_add_noaddr(&s->uplink_netif, NULL, uplink_netif_init, tcpip_input)) return ERR_IF;
        s->uplink_added = true;
    }
    pthread_mutex_lock(&state_lock);
    memcpy(s->lease, c->lease, 4);
    s->uplink_deadline = c->deadline;
    pthread_mutex_unlock(&state_lock);
    ip4_addr_t address, mask, gateway;
    memcpy(&address.addr, c->lease, 4);
    mask.addr = PP_HTONL(0xffffffff);
    gateway.addr = 0;
    netif_set_addr(&s->uplink_netif, &address, &mask, &gateway);
    if (netif_default != &s->uplink_netif) s->direct_netif = netif_default;
    IP_SET_TYPE_VAL(s->gateway_dns, IPADDR_TYPE_V6);
    memcpy(ip_2_ip6(&s->gateway_dns)->addr, s->gateway, 16);
    for (unsigned i = 0; i < DNS_MAX_SERVERS; i++) {
        s->previous_dns[i] = *dns_getserver(i);
        dns_setserver(i, &s->gateway_dns);
    }
    netif_set_link_up(&s->uplink_netif);
    netif_set_up(&s->uplink_netif);
    netif_set_default(&s->uplink_netif);
    atomic_store(&s->direct_successes, 0);
    atomic_store(&s->uplink_active, true);
    return ERR_OK;
}
static bool uplink_route_live(struct mesh_state* s, unsigned generation)
{
    if (!atomic_load(&s->active) || atomic_load(&s->generation) != generation
        || !wendy_conf_is_current() || wendy_pki_reset_in_progress()) return false;
    int64_t now = esp_timer_get_time();
    pthread_mutex_lock(&state_lock);
    bool valid = identity_live(s, now) && s->own_deadline_us > now
        && wm_directory_address(&s->directory, s->gateway, now);
    pthread_mutex_unlock(&state_lock);
    return valid;
}
static int uplink_transfer(struct mesh_state* s, unsigned generation,
    wendy_pki_connection* c, uint8_t* data, size_t size, bool writing, int64_t deadline)
{
    while (size) {
        int64_t now = esp_timer_get_time();
        if (!uplink_route_live(s, generation) || now >= deadline) return -1;
        ssize_t n = writing ? wendy_pki_write(c, data, size) : wendy_pki_read(c, data, size);
        if (n > 0) { data += n; size -= n; continue; }
        if (n != -2 && n != -3) return -1;
        int64_t slice = now + 200000;
        if (slice > deadline) slice = deadline;
        if (wendy_pki_wait(c, n == -3, slice) < 0) return -1;
    }
    return 0;
}
static void uplink_task(void* unused)
{
    (void)unused;
    struct mesh_state* s = state;
    bool cloud_started = false;
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(1000));
        unsigned generation = atomic_load(&s->generation);
        if (!atomic_load(&s->uplink_workers_ready)) continue;
        if (!uplink_route_live(s, generation)) continue;
        /* Wi-Fi may never associate. Start Cloud once the mesh stack works so
         * its normal direct attempts can request fallback without an AP event. */
        if (!cloud_started) cloud_started = wendy_cloud_start() == ESP_OK;
        if (!cloud_started || wendy_cloud_connect_failures() < 2) continue;
        char host[48];
        ip6_addr_t gateway = { 0 };
        memcpy(gateway.addr, s->gateway, 16);
        if (!ip6addr_ntoa_r(&gateway, host, sizeof host)) continue;
        wendy_pki_connection* c = NULL;
        int64_t expires = 0;
        if (wendy_pki_gateway_connect(host, CONFIG_WENDY_MESH_GATEWAY_DEVICE, &c, &expires)
            != ESP_OK) { vTaskDelay(pdMS_TO_TICKS(5000)); continue; }
        uint8_t response[3], lease[4];
        int64_t deadline = esp_timer_get_time() + INT64_C(8000000);
        if (expires < deadline) deadline = expires;
        struct uplink_change change = { .s = s, .action = 1, .generation = generation,
            .deadline = expires };
        bool granted = !uplink_transfer(s, generation, c, response, sizeof response, false, deadline)
            && wm_uplink_lease(response, lease);
        if (granted) {
            memcpy(change.lease, lease, 4);
            granted = tcpip_api_call(change_uplink, &change.call) == ERR_OK;
        }
        if (granted) {
            wendy_cloud_network_changed();
            ESP_LOGI(TAG, "Cloud fallback using authenticated mesh gateway");
        }
        int64_t heartbeat = esp_timer_get_time();
        bool recovered = false;
        while (granted && atomic_load(&s->uplink_active) && uplink_route_live(s, generation)
            && esp_timer_get_time() < expires) {
            if (atomic_load(&s->direct_successes) >= 2) { recovered = true; break; }
            int64_t now = esp_timer_get_time();
            if (now - heartbeat >= INT64_C(10000000)) {
                uint8_t byte = 1;
                deadline = now + INT64_C(8000000);
                if (expires < deadline) deadline = expires;
                if (uplink_transfer(s, generation, c, &byte, 1, true, deadline)
                    || uplink_transfer(s, generation, c, &byte, 1, false, deadline) || byte != 1)
                    break;
                change.action = 3;
                if (tcpip_api_call(change_uplink, &change.call) != ERR_OK) break;
                heartbeat = esp_timer_get_time();
            }
            vTaskDelay(pdMS_TO_TICKS(200));
        }
        change.action = 0;
        tcpip_api_call(change_uplink, &change.call);
        wendy_pki_close(c);
        if (recovered) {
            wendy_cloud_reset_failures();
            ESP_LOGI(TAG, "direct Cloud path recovered; mesh Internet lease withdrawn");
        } else if (granted) ESP_LOGW(TAG, "mesh Internet lease lost; borrowed routes withdrawn");
        if (granted) wendy_cloud_network_changed();
        vTaskDelay(pdMS_TO_TICKS(5000));
    }
}
/* Keep health checks separate from lease heartbeats: slow DNS or TLS must not
 * prevent the borrower withdrawing an expired lease or refreshing a live one. */
static void uplink_probe_task(void* unused)
{
    (void)unused;
    struct mesh_state* s = state;
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(60000));
        if (!atomic_load(&s->uplink_active)) continue;
        unsigned generation = atomic_load(&s->generation);
        struct uplink_change c = { .s = s, .action = 2 };
        tcpip_api_call(change_uplink, &c.call);
        bool healthy = c.direct_name[0] && wendy_pki_probe_direct(c.direct_name, c.direct_dns);
        if (!atomic_load(&s->uplink_active) || atomic_load(&s->generation) != generation) continue;
        if (healthy) atomic_fetch_add(&s->direct_successes, 1);
        else atomic_store(&s->direct_successes, 0);
    }
}
#endif
static void mesh_task(void* unused)
{
    (void)unused;
    struct mesh_state* s = state;
#if CONFIG_WENDY_MESH_CLOUD_UPLINK
    TaskHandle_t uplink = NULL, probe = NULL;
#endif
    for (;;)
    {
#if CONFIG_WENDY_MESH_CLOUD_UPLINK
        if (!uplink) xTaskCreate(uplink_task, "mesh_uplink", MESH_STACK_BYTES, NULL, 3, &uplink);
        if (!probe) xTaskCreate(uplink_probe_task, "uplink_probe", MESH_STACK_BYTES, NULL, 2, &probe);
        atomic_store(&s->uplink_workers_ready, uplink && probe);
        if (!uplink || !probe) ESP_LOGW(TAG, "not enough task memory for Cloud fallback; mesh remains available");
#endif
        if (wendy_conf_is_current() && wendy_conf_has_enrollment()
            && !wendy_pki_reset_in_progress())
        {
            publish_phase(WENDY_MESH_CONNECTING);
            session(s);
            pthread_mutex_lock(&state_lock);
            if (phase != WENDY_MESH_DISCOVERING && phase != WENDY_MESH_WAITING_WIFI)
                phase = WENDY_MESH_RETRYING;
            pthread_mutex_unlock(&state_lock);
        }
        else publish_phase(WENDY_MESH_WAITING_ENROLLMENT);
        atomic_store(&s->active, false);
        struct netif_change change = { .s = s, .up = false };
        tcpip_api_call(change_netif, &change.call);
        if (s->connection)
        {
            wendy_pki_close(s->connection);
            s->connection = NULL;
        }
        if (s->carrier.close) s->carrier.close();
        memset(&s->carrier, 0, sizeof s->carrier);
        pthread_mutex_lock(&state_lock);
        s->own_deadline_us = 0;
        memset(s->peer, 0, sizeof s->peer);
        memset(s->active_carrier, 0, sizeof s->active_carrier);
        pthread_mutex_unlock(&state_lock);
        memset(&s->assembler, 0, sizeof s->assembler);
        xQueueReset(s->queue);
#if CONFIG_WENDY_MESH_ESPNOW
        /* Avoid two rebooting peers repeating disjoint rendezvous windows. */
        vTaskDelay(pdMS_TO_TICKS(500 + esp_random() % 1500));
#elif CONFIG_WENDY_MESH_WIFI_BLE
        vTaskDelay(pdMS_TO_TICKS(1000));
#else
        vTaskDelay(pdMS_TO_TICKS(5000));
#endif
    }
}
/* TEST-ONLY heap diagnostics for the XIAO ESP_ERR_NO_MEM investigation. */
#define MESH_HEAP_DIAG(where)                                                                  \
    ESP_LOGW(TAG,                                                                              \
        "heapdiag[%s] internal free=%u largest=%u min=%u | dma free=%u largest=%u | "          \
        "spiram free=%u largest=%u",                                                           \
        (where),                                                                               \
        (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),              \
        (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),     \
        (unsigned)heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),      \
        (unsigned)heap_caps_get_free_size(MALLOC_CAP_DMA),                                     \
        (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_DMA),                            \
        (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM),                                  \
        (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM))
static void mesh_heap_diag_tick(void* unused)
{
    (void)unused;
    MESH_HEAP_DIAG("periodic");
    TaskHandle_t task = mesh_task_handle;
    if (task)
        ESP_LOGW(TAG, "heapdiag mesh stack high-water free=%u of %u",
            (unsigned)uxTaskGetStackHighWaterMark(task), (unsigned)MESH_STACK_BYTES);
}
static void mesh_heap_diag_arm(void)
{
    static esp_timer_handle_t timer;
    if (timer)
        return;
    const esp_timer_create_args_t args = { .callback = mesh_heap_diag_tick, .name = "heapdiag" };
    if (esp_timer_create(&args, &timer) == ESP_OK)
        esp_timer_start_periodic(timer, 30 * 1000 * 1000);
}
static esp_err_t wendy_mesh_start_impl(void);
esp_err_t wendy_mesh_start(void)
{
    MESH_HEAP_DIAG("mesh_start entry");
    ESP_LOGW(TAG, "heapdiag sizeof(mesh_state)=%u stack=%u psram-admission=%u",
        (unsigned)sizeof(struct mesh_state), (unsigned)MESH_STACK_BYTES,
        (unsigned)(sizeof(struct mesh_state) + 512 * 1024));
    heap_caps_print_heap_info(MALLOC_CAP_INTERNAL);
    esp_err_t err = wendy_mesh_start_impl();
    MESH_HEAP_DIAG(err == ESP_OK ? "mesh_start ok" : "mesh_start failed");
    mesh_heap_diag_arm();
    return err;
}
static esp_err_t wendy_mesh_start_impl(void)
{
    if (mesh_task_handle)
        return ESP_OK;
#if (!CONFIG_WENDY_MESH_AUTO_DISCOVER && !CONFIG_WENDY_MESH_WIFI_BLE) || CONFIG_WENDY_MESH_CLOUD_UPLINK
    uint8_t router[16];
#endif
#if !CONFIG_WENDY_MESH_AUTO_DISCOVER && !CONFIG_WENDY_MESH_WIFI_BLE
    if (wm_uuid_parse(CONFIG_WENDY_MESH_ROUTER_DEVICE, router))
        return ESP_ERR_INVALID_ARG;
#endif
    /* PSRAM is required for this experimental profile. Refuse allocation if
     * concurrent TLS/chain verification cannot retain at least 512 KiB free. */
    if (heap_caps_get_free_size(MALLOC_CAP_SPIRAM) < sizeof(struct mesh_state) + 512 * 1024)
    {
        ESP_LOGE(TAG, "heapdiag FAIL: PSRAM admission check");
        return ESP_ERR_NO_MEM;
    }
    struct mesh_state* s = heap_caps_calloc(1, sizeof *s, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!s)
    {
        ESP_LOGE(TAG, "heapdiag FAIL: PSRAM state calloc");
        return ESP_ERR_NO_MEM;
    }
    s->queue = xQueueCreateStatic(
        MESH_QUEUE_PACKETS, sizeof(struct queued_packet), s->queue_storage, &s->queue_control);
    if (!s->queue)
    {
        ESP_LOGE(TAG, "heapdiag FAIL: queue");
        free(s);
        return ESP_ERR_NO_MEM;
    }
#if CONFIG_WENDY_MESH_CLOUD_UPLINK
    if (wm_uuid_parse(CONFIG_WENDY_MESH_GATEWAY_DEVICE, router)) {
        vQueueDelete(s->queue); free(s); return ESP_ERR_INVALID_ARG;
    }
    wm_address(router, s->gateway);
#endif
    pthread_mutex_lock(&state_lock);
    state = s;
    phase = WENDY_MESH_WAITING_ENROLLMENT;
    pthread_mutex_unlock(&state_lock);
    if (xTaskCreate(mesh_task, "wendy_mesh", MESH_STACK_BYTES, NULL, 4, &mesh_task_handle)
        != pdPASS)
    {
        ESP_LOGE(TAG, "heapdiag FAIL: xTaskCreate(wendy_mesh, %u-byte internal stack)",
            (unsigned)MESH_STACK_BYTES);
        pthread_mutex_lock(&state_lock);
        state = NULL;
        phase = WENDY_MESH_UNAVAILABLE;
        pthread_mutex_unlock(&state_lock);
        vQueueDelete(s->queue);
        free(s);
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}
