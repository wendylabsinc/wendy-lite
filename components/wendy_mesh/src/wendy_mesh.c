#include "wendy_mesh.h"
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
    struct wm_directory directory;
    struct wm_epoch epoch;
    struct wm_assembler assembler;
    struct netif netif;
    struct wendy_pki_mesh_identity identity;
    wendy_pki_connection* connection;
    QueueHandle_t queue;
    StaticQueue_t queue_control;
    uint8_t queue_storage[MESH_QUEUE_PACKETS * sizeof(struct queued_packet)];
    char control[WENDY_MESH_CONTROL_MAX + 1];
    uint8_t certificate_scratch[32768];
    uint8_t own_address[16], device[16];
    uint64_t revision, router_id;
    uint16_t seqno, hello_seq;
    uint32_t packet_id;
    int64_t own_deadline_us;
    bool interface_added;
    atomic_bool active;
};
/* Protocol storage has a compile-time cap, including the certificate decode
 * workspace. TLS/X.509 allocations are separately bounded by input limits. */
_Static_assert(sizeof(struct mesh_state) < 128 * 1024, "mesh protocol storage exceeds 128 KiB");
static _Atomic(struct mesh_state*) state;
static pthread_mutex_t state_lock = PTHREAD_MUTEX_INITIALIZER;
static TaskHandle_t mesh_task_handle;
static const char* TAG = "wendy_mesh";

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
    return wm_ip_valid(p, n) && (p[6] == 6 || p[6] == 17 || p[6] == 58);
}
static err_t output_ip6(struct netif* netif, struct pbuf* p, const ip6_addr_t* destination)
{
    (void)destination;
    struct mesh_state* s = netif->state;
    struct queued_packet packet;
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
            if (!netif_add_noaddr(&s->netif, s, mesh_netif_init, tcpip_input))
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
    int fd = wendy_pki_fd(s->connection);
    if (fd < 0 || fd >= FD_SETSIZE)
        return -1;
    fd_set rd, wr;
    FD_ZERO(&rd);
    FD_ZERO(&wr);
    if (writing)
        FD_SET(fd, &wr);
    else
        FD_SET(fd, &rd);
    int64_t left = deadline - now;
    if (left > 200000)
        left = 200000;
    struct timeval timeout = { .tv_sec = 0, .tv_usec = left };
    int result = select(fd + 1, &rd, &wr, NULL, &timeout);
    return result < 0 ? -1 : 0;
}
static int transfer(struct mesh_state* s, void* buffer, size_t size, bool writing)
{
    uint8_t* p = buffer;
    int64_t deadline = esp_timer_get_time() + INT64_C(5000000);
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
        struct wendy_pki_mesh_peer peer;
        if (wendy_pki_mesh_verify_bundle(
                s->connection, der, sizes, count, signed_now(s, now_us) / 1000, &peer))
            return -1;
        if (!strcmp(peer.device, s->identity.device))
            return 0;
        uint8_t peer_uuid[16], peer_address[16];
        if (wm_uuid_parse(peer.device, peer_uuid))
            return -1;
        wm_address(peer_uuid, peer_address);
        if (!memcmp(peer_address, s->own_address, 16))
            return -1;
        pthread_mutex_lock(&state_lock);
        int result = wm_directory_add(&s->directory, &peer);
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
static int receive_frame(struct mesh_state* s)
{
    uint8_t header[5];
    if (transfer(s, header, sizeof header, false))
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
    if (!allowed)
        return -1;
    struct pbuf* p = pbuf_alloc(PBUF_RAW, assembled, PBUF_RAM);
    if (!p)
        return -1;
    if (pbuf_take(p, ip, assembled) != ERR_OK || tcpip_input(p, &s->netif) != ERR_OK)
    {
        pbuf_free(p);
        return -1;
    }
    return 0;
}
static int session(struct mesh_state* s)
{
    if (wendy_pki_mesh_connect(CONFIG_WENDY_MESH_ROUTER_HOST, CONFIG_WENDY_MESH_ROUTER_PORT,
            CONFIG_WENDY_MESH_ROUTER_DEVICE, &s->connection, &s->identity)
        != ESP_OK)
        return -1;
    if (wm_uuid_parse(s->identity.device, s->device))
        return -1;
    pthread_mutex_lock(&state_lock);
    int bound = wm_directory_bind(&s->directory, &s->epoch, &s->identity);
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
        s->identity.device, CONFIG_WENDY_MESH_ROUTER_DEVICE, s->control, sizeof s->control);
    if (size < 0 || write_control(s, s->control, size, true))
        return -1;
    uint8_t header[4];
    if (transfer(s, header, 4, false))
        return -1;
    size = wm_get32(header);
    if (size < 1 || size > 512 || transfer(s, s->control, size, false)
        || wm_hello_check(s->control, size, s->identity.device, CONFIG_WENDY_MESH_ROUTER_DEVICE))
        return -1;
    if (send_bundle(s) || announce(s, true))
        return -1;
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
            atomic_store(&s->active, true);
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
        int fd = wendy_pki_fd(s->connection);
        fd_set rd;
        FD_ZERO(&rd);
        FD_SET(fd, &rd);
        struct timeval timeout = { .tv_usec = 20000 };
        int ready
            = wendy_pki_pending(s->connection) ? 1 : select(fd + 1, &rd, NULL, NULL, &timeout);
        if (ready < 0 || (ready > 0 && receive_frame(s)))
            return -1;
    }
    return -1;
}
static void mesh_task(void* unused)
{
    (void)unused;
    struct mesh_state* s = state;
    for (;;)
    {
        if (wendy_conf_is_current() && wendy_conf_has_enrollment()
            && !wendy_pki_reset_in_progress())
            session(s);
        atomic_store(&s->active, false);
        struct netif_change change = { .s = s, .up = false };
        tcpip_api_call(change_netif, &change.call);
        if (s->connection)
        {
            wendy_pki_close(s->connection);
            s->connection = NULL;
        }
        pthread_mutex_lock(&state_lock);
        s->own_deadline_us = 0;
        pthread_mutex_unlock(&state_lock);
        memset(&s->assembler, 0, sizeof s->assembler);
        xQueueReset(s->queue);
        vTaskDelay(pdMS_TO_TICKS(5000));
    }
}
esp_err_t wendy_mesh_start(void)
{
    if (mesh_task_handle)
        return ESP_OK;
    uint8_t router[16];
    if (!CONFIG_WENDY_MESH_ROUTER_HOST[0] || wm_uuid_parse(CONFIG_WENDY_MESH_ROUTER_DEVICE, router))
        return ESP_ERR_INVALID_ARG;
    /* PSRAM is required for this experimental profile. Refuse allocation if
     * concurrent TLS/chain verification cannot retain at least 512 KiB free. */
    if (heap_caps_get_free_size(MALLOC_CAP_SPIRAM) < sizeof(struct mesh_state) + 512 * 1024)
        return ESP_ERR_NO_MEM;
    struct mesh_state* s = heap_caps_calloc(1, sizeof *s, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!s)
        return ESP_ERR_NO_MEM;
    s->queue = xQueueCreateStatic(
        MESH_QUEUE_PACKETS, sizeof(struct queued_packet), s->queue_storage, &s->queue_control);
    if (!s->queue)
    {
        free(s);
        return ESP_ERR_NO_MEM;
    }
    state = s;
    if (xTaskCreate(mesh_task, "wendy_mesh", MESH_STACK_BYTES, NULL, 4, &mesh_task_handle)
        != pdPASS)
    {
        state = NULL;
        vQueueDelete(s->queue);
        free(s);
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}
