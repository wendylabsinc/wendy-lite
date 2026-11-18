#include "espnow_carrier.h"
#include "actor_driver.h"
#include "wendy_net_espnow_hosted.h"
#include "wendy_net_ble_protocol.h"
#include "wendy_wifi.h"

#include "esp_random.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "lwip/inet.h"
#include "lwip/netif.h"
#include "lwip/sockets.h"
#include "lwip/tcpip.h"
#include "lwip/priv/tcpip_priv.h"
#include "lwip/prot/tcp.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#if CONFIG_WENDY_WIFI_ENABLED && (CONFIG_IDF_TARGET_ESP32C5 || CONFIG_IDF_TARGET_ESP32C6 || \
                                 (CONFIG_IDF_TARGET_ESP32P4 && CONFIG_ESP_HOSTED_ENABLE_PEER_DATA_TRANSFER))
#if CONFIG_IDF_TARGET_ESP32P4
#include "esp_hosted_misc.h"
#else
#include "wendy_net_espnow_peers.h"
#endif

enum { IP_MTU = 1280, HEADER_SIZE = 5, QUEUE_DEPTH = 4, AD_SIZE = 40 };
enum { IPV6_HEADER_SIZE = 40, TCP_HEADER_SIZE = 20 };
enum { PRESENCE = 1, IPV6 = 2 };
static const uint8_t broadcast[6] = {255, 255, 255, 255, 255, 255};
static const uint8_t prefix[] = {'W', 'N', 'E', 1};
struct frame {
    uint8_t mac[6];
    uint8_t bytes[HEADER_SIZE + IP_MTU];
    uint16_t size;
    unsigned generation;
};
static struct netif interface;
static uint8_t station[6];
static struct {
    const void *link;
    uint8_t mac[6], rate;
} link_rates[CONFIG_WENDY_NET_MAX_LINKS];
static QueueHandle_t rx, tx;
static atomic_uint generation, receiving;
static atomic_bool transmitting;
static unsigned running_generation, interface_index;
static int listener = -1;
static bool backend_started, radio_paused;
static int64_t advertise_at, send_deadline;

static void address_from_mac(uint8_t out[16], const uint8_t mac[6])
{
    const uint8_t address[16] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0,
        mac[0] ^ 2, mac[1], mac[2], 0xff, 0xfe, mac[3], mac[4], mac[5]};
    memcpy(out, address, sizeof address);
}

static bool mac_from_address(uint8_t mac[6], const uint8_t address[16])
{
    mac[0] = address[8] ^ 2;
    mac[1] = address[9];
    mac[2] = address[10];
    memcpy(mac + 3, address + 13, 3);
    uint8_t expected[16];
    address_from_mac(expected, mac);
    return !(mac[0] & 1) && !memcmp(expected, address, sizeof expected);
}

void wn_espnow_set_link_rate(const void *link, const char *address, unsigned rate)
{
    uint8_t ip[16], mac[6];
    if (!wn_espnow_rate_valid(rate) || inet_pton(AF_INET6, address, ip) != 1 ||
        !mac_from_address(mac, ip))
        return;
    for (unsigned i = 0; i < CONFIG_WENDY_NET_MAX_LINKS; i++) {
        if (!link_rates[i].link || link_rates[i].link == link) {
            link_rates[i].link = link;
            memcpy(link_rates[i].mac, mac, sizeof mac);
            link_rates[i].rate = (uint8_t)rate;
            return;
        }
    }
}

void wn_espnow_clear_link_rate(const void *link)
{
    for (unsigned i = 0; i < CONFIG_WENDY_NET_MAX_LINKS; i++)
        if (link_rates[i].link == link)
            link_rates[i].link = NULL;
}

static unsigned rate_for(const uint8_t mac[6])
{
    unsigned rate = 0;
    for (unsigned i = 0; i < CONFIG_WENDY_NET_MAX_LINKS; i++)
        if (link_rates[i].link && !memcmp(link_rates[i].mac, mac, 6) &&
            (!rate || link_rates[i].rate < rate))
            rate = link_rates[i].rate;
    return rate ? rate : 1;
}

static void enqueue_received(const uint8_t source[6], const uint8_t destination[6],
                             const uint8_t *bytes, size_t size, unsigned current)
{
    if (!bytes || size <= HEADER_SIZE || size > HEADER_SIZE + IP_MTU ||
        memcmp(bytes, prefix, sizeof prefix))
        return;
    bool bcast = !memcmp(destination, broadcast, 6);
    if (bcast ? bytes[4] != PRESENCE || size != AD_SIZE :
                bytes[4] != IPV6 || size < HEADER_SIZE + IPV6_HEADER_SIZE + TCP_HEADER_SIZE)
        return;
    struct frame packet;
    memcpy(packet.mac, source, 6);
    memcpy(packet.bytes, bytes, size);
    packet.size = (uint16_t)size;
    packet.generation = current;
    if (xQueueSend(rx, &packet, 0) == pdTRUE)
        wnad_wake();
}

static void queue_received(const uint8_t source[6], const uint8_t destination[6],
                           const uint8_t *bytes, size_t size)
{
    unsigned current = atomic_load(&generation);
    if (!(current & 1))
        return;
    atomic_fetch_add(&receiving, 1);
    /* A callback that raced with stop must not use a retired queue, even if
     * another generation has already started. */
    if (atomic_load(&generation) == current)
        enqueue_received(source, destination, bytes, size, current);
    atomic_fetch_sub(&receiving, 1);
}

static void completed_send(void)
{
    atomic_store(&transmitting, false);
    wnad_wake();
}

#if CONFIG_IDF_TARGET_ESP32P4
static atomic_bool hosted_capability, hosted_rate_capable, hosted_started, hosted_wants_start;
static bool hosted_registered;

static void hosted_event(uint32_t id, const uint8_t *bytes, size_t size, void *context)
{
    (void)id;
    (void)context;
    if (size < 2 || bytes[0] != WN_ESPNOW_HOSTED_VERSION)
        return;
    switch (bytes[1]) {
    case WNE_CAPABILITY:
        atomic_store(&hosted_rate_capable, size >= 3 &&
                                          (bytes[2] & WN_ESPNOW_HOSTED_RATE_CAPABILITY));
        atomic_store(&hosted_capability, true);
        break;
    case WNE_STARTED:
        if (atomic_load(&hosted_wants_start))
            atomic_store(&hosted_started, size == 3 && bytes[2] == 0);
        break;
    case WNE_RECEIVED:
        if (size > 14 && size <= WN_ESPNOW_HOSTED_PAYLOAD + 14)
            queue_received(bytes + 2, bytes + 8, bytes + 14, size - 14);
        return;
    case WNE_SENT:
        completed_send();
        return;
    }
    wnad_wake();
}

static esp_err_t hosted_command(uint8_t operation, unsigned channel)
{
    const uint8_t command[] = {WN_ESPNOW_HOSTED_VERSION, operation, (uint8_t)channel};
    return esp_hosted_send_custom_data(WN_ESPNOW_HOSTED_MESSAGE, command, sizeof command);
}

static esp_err_t radio_start(unsigned channel)
{
    if (!hosted_registered) {
        esp_err_t err = esp_hosted_register_custom_callback(WN_ESPNOW_HOSTED_MESSAGE,
                                                             hosted_event, NULL);
        if (err != ESP_OK)
            return err;
        hosted_registered = true;
    }
    if (!atomic_load(&hosted_capability)) {
        (void)hosted_command(WNE_PROBE, 0);
        return ESP_ERR_NOT_SUPPORTED;
    }
    if (atomic_load(&hosted_started))
        return ESP_OK;
    atomic_store(&hosted_wants_start, true);
    esp_err_t err = hosted_command(WNE_START, channel);
    if (err != ESP_OK)
        return err;
    return atomic_load(&hosted_started) ? ESP_OK : ESP_ERR_INVALID_STATE;
}

static void radio_stop(void)
{
    if (atomic_exchange(&hosted_wants_start, false))
        (void)hosted_command(WNE_STOP, 0);
    atomic_store(&hosted_started, false);
}

static esp_err_t radio_send(const struct frame *packet)
{
    unsigned rate = rate_for(packet->mac);
    size_t header = rate > 1 ? 9 : 8;
    uint8_t data[9 + WN_ESPNOW_HOSTED_PAYLOAD] = {WN_ESPNOW_HOSTED_VERSION,
                                                rate > 1 ? WNE_SEND_AT_RATE : WNE_SEND};
    memcpy(data + 2, packet->mac, 6);
    data[8] = (uint8_t)rate;
    memcpy(data + header, packet->bytes, packet->size);
    return esp_hosted_send_custom_data(WN_ESPNOW_HOSTED_MESSAGE, data, packet->size + header);
}
#else
static struct wn_espnow_peers radio_peers;

static void receive_frame(const esp_now_recv_info_t *info, const uint8_t *bytes, int size)
{
    if (info && size > 0)
        queue_received(info->src_addr, info->des_addr, bytes, (size_t)size);
}

static void sent_frame(const esp_now_send_info_t *info, esp_now_send_status_t status)
{
    (void)info;
    (void)status;
    completed_send();
}

static esp_err_t radio_start(unsigned channel)
{
    (void)channel;
    esp_err_t err = esp_now_init();
    if (err != ESP_OK)
        return err;
    radio_peers.count = 0;
    if ((err = wn_espnow_add_peer(broadcast)) != ESP_OK ||
        (err = esp_now_register_send_cb(sent_frame)) != ESP_OK ||
        (err = esp_now_register_recv_cb(receive_frame)) != ESP_OK)
        (void)esp_now_deinit();
    return err;
}

static void radio_stop(void)
{
    (void)esp_now_deinit();
}

static esp_err_t radio_send(const struct frame *packet)
{
    esp_err_t err = wn_espnow_prepare_peer(&radio_peers, packet->mac, rate_for(packet->mac));
    return err == ESP_OK ? esp_now_send(packet->mac, packet->bytes, packet->size) : err;
}
#endif

static err_t send_ip(struct netif *netif, struct pbuf *p, const ip6_addr_t *destination)
{
    (void)netif;
    struct frame packet;
    unsigned current = atomic_load(&generation);
    if (!(current & 1) || p->tot_len > IP_MTU ||
        !mac_from_address(packet.mac, (const uint8_t *)destination->addr))
        return ERR_RTE;
    memcpy(packet.bytes, prefix, sizeof prefix);
    packet.bytes[4] = IPV6;
    if (pbuf_copy_partial(p, packet.bytes + HEADER_SIZE, p->tot_len, 0) != p->tot_len)
        return ERR_BUF;
    packet.size = HEADER_SIZE + p->tot_len;
    packet.generation = current;
    if (xQueueSend(tx, &packet, 0) != pdTRUE)
        return ERR_MEM;
    wnad_wake();
    return ERR_OK;
}

static err_t init_interface(struct netif *netif)
{
    netif->name[0] = 'w';
    netif->name[1] = 'e';
    netif->mtu = IP_MTU;
    netif->output_ip6 = send_ip;
    netif->flags = 0;
    return ERR_OK;
}

static err_t add_interface(struct tcpip_api_call_data *call)
{
    (void)call;
    if (!netif_add_noaddr(&interface, NULL, init_interface, tcpip_input))
        return ERR_IF;
    ip6_addr_t address = {0};
    address_from_mac((uint8_t *)address.addr, station);
    netif_ip6_addr_set(&interface, 0, &address);
    netif_ip6_addr_set_state(&interface, 0, IP6_ADDR_PREFERRED);
    netif_set_link_up(&interface);
    netif_set_up(&interface);
    interface_index = netif_get_index(&interface);
    return ERR_OK;
}

static err_t remove_interface(struct tcpip_api_call_data *call)
{
    (void)call;
    netif_set_down(&interface);
    netif_remove(&interface);
    interface_index = 0;
    return ERR_OK;
}

static int open_socket(void)
{
    int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0)
        return -1;
    struct ifreq bind_interface = {0};
    snprintf(bind_interface.ifr_name, sizeof bind_interface.ifr_name, "we%u", interface_index - 1);
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &bind_interface, sizeof bind_interface) ||
        !wnad_prepare_socket(fd)) {
        close(fd);
        return -1;
    }
    return fd;
}

static bool keepalive(int fd)
{
    int yes = 1, idle = 15, interval = 5, count = 3;
    return !setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof yes) &&
        !setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof idle) &&
        !setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof interval) &&
        !setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &count, sizeof count);
}

bool wn_espnow_supported(void)
{
    return true;
}

unsigned wn_espnow_rate_limit(unsigned configured)
{
#if CONFIG_IDF_TARGET_ESP32P4
    if (!atomic_load(&hosted_rate_capable))
        return 1;
#endif
    return wn_espnow_rate_valid(configured) ? configured : 1;
}

esp_err_t wn_espnow_start(unsigned channel)
{
    if (listener >= 0)
        return ESP_OK;
    esp_err_t err = wendy_wifi_espnow_channel(channel);
    if (err != ESP_OK) {
        wendy_wifi_espnow_release();
        return err;
    }
    err = esp_wifi_get_mac(WIFI_IF_STA, station);
    if (err != ESP_OK)
        goto fail;
    err = radio_start(channel);
    if (err != ESP_OK) {
#if CONFIG_IDF_TARGET_ESP32P4
        /* A START reply arrives on the hosted event stream. Keep the radio
         * available until the next poll can consume that result. */
        if (err == ESP_ERR_INVALID_STATE && atomic_load(&hosted_capability))
            return err;
#endif
        goto fail;
    }
    backend_started = true;
    rx = xQueueCreate(QUEUE_DEPTH, sizeof(struct frame));
    tx = xQueueCreate(QUEUE_DEPTH, sizeof(struct frame));
    if (!rx || !tx) {
        err = ESP_ERR_NO_MEM;
        goto fail;
    }
    atomic_store(&transmitting, false);
    struct tcpip_api_call_data call;
    if (tcpip_api_call(add_interface, &call) != ERR_OK) {
        err = ESP_FAIL;
        goto fail;
    }
    listener = open_socket();
    struct sockaddr_in6 address = {.sin6_family = AF_INET6,
        .sin6_port = htons(WN_ESPNOW_PORT), .sin6_scope_id = interface_index};
    address_from_mac(address.sin6_addr.s6_addr, station);
    if (listener < 0 || bind(listener, (struct sockaddr *)&address, sizeof address) ||
        listen(listener, 2)) {
        err = ESP_FAIL;
        goto fail;
    }
    running_generation = atomic_fetch_add(&generation, 1) + 1;
    advertise_at = esp_random() % 1000000;
    radio_paused = false;
    return ESP_OK;

fail:
    wn_espnow_stop();
    return err;
}

void wn_espnow_stop(void)
{
    memset(link_rates, 0, sizeof link_rates);
    if (running_generation) {
        atomic_fetch_add(&generation, 1);
        running_generation = 0;
    }
    if (listener >= 0) {
        close(listener);
        listener = -1;
    }
    if (interface_index) {
        struct tcpip_api_call_data call;
        (void)tcpip_api_call(remove_interface, &call);
    }
#if CONFIG_IDF_TARGET_ESP32P4
    if (backend_started || atomic_load(&hosted_wants_start))
#else
    if (backend_started)
#endif
        radio_stop();
    backend_started = false;
    atomic_store(&transmitting, false);
    while (atomic_load(&receiving))
        vTaskDelay(1);
    if (rx)
        vQueueDelete(rx);
    if (tx)
        vQueueDelete(tx);
    rx = tx = NULL;
    wendy_wifi_espnow_release();
}

bool wn_espnow_channel_live(unsigned channel)
{
    if (listener < 0)
        return false;
    enum wendy_wifi_espnow_state state = wendy_wifi_espnow_state(channel);
    int64_t now = esp_timer_get_time();
    radio_paused = state == WENDY_WIFI_ESPNOW_SCANNING;
    if (radio_paused) {
        /* The radio may finish an outstanding send after the scan. Keep the
         * interface and its TCP sockets open across the off-channel dwell. */
        send_deadline = now + INT64_C(2000000);
        return true;
    }
    return state == WENDY_WIFI_ESPNOW_READY &&
           (!atomic_load(&transmitting) || now < send_deadline);
}

int wn_espnow_listener(void)
{
    return listener;
}

int wn_espnow_accept(struct wn_candidate *candidate)
{
    struct sockaddr_in6 address;
    socklen_t size = sizeof address;
    int fd = accept(listener, (struct sockaddr *)&address, &size);
    if (fd < 0)
        return -1;
    if (!inet_ntop(AF_INET6, &address.sin6_addr, candidate->address, sizeof candidate->address) ||
        !keepalive(fd)) {
        close(fd);
        return -1;
    }
    return fd;
}

int wn_espnow_connect(const struct wn_candidate *candidate, bool *connecting)
{
    struct sockaddr_in6 address = {.sin6_family = AF_INET6,
        .sin6_port = htons(candidate->port), .sin6_scope_id = interface_index};
    if (listener < 0 || inet_pton(AF_INET6, candidate->address, &address.sin6_addr) != 1)
        return -1;
    int fd = open_socket();
    if (fd < 0)
        return -1;
    if (!keepalive(fd)) {
        close(fd);
        return -1;
    }
    int result = connect(fd, (struct sockaddr *)&address, sizeof address);
    if (result && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    *connecting = result != 0;
    return fd;
}

static void deliver_ip(const struct frame *packet, bool accepting)
{
    const uint8_t *bytes = packet->bytes + HEADER_SIZE;
    unsigned size = packet->size - HEADER_SIZE;
    uint8_t expected[16];
    address_from_mac(expected, packet->mac);
    if (size < IPV6_HEADER_SIZE + TCP_HEADER_SIZE || bytes[0] >> 4 != 6 ||
        bytes[6] != IPPROTO_TCP ||
        size != IPV6_HEADER_SIZE + ((unsigned)bytes[4] << 8) + bytes[5] ||
        memcmp(bytes + 8, expected, 16))
        return;
    address_from_mac(expected, station);
    if (memcmp(bytes + 24, expected, 16))
        return;
    const uint8_t *tcp = bytes + IPV6_HEADER_SIZE;
    unsigned tcp_header_size = (tcp[12] >> 4) * 4u;
    if (tcp_header_size < TCP_HEADER_SIZE || tcp_header_size > size - IPV6_HEADER_SIZE)
        return;
    unsigned source_port = ((unsigned)tcp[0] << 8) | tcp[1];
    unsigned destination_port = ((unsigned)tcp[2] << 8) | tcp[3];
    bool incoming_syn = (tcp[13] & (TCP_SYN | TCP_ACK)) == TCP_SYN;
    if (incoming_syn ? (!accepting || destination_port != WN_ESPNOW_PORT)
                     : (source_port != WN_ESPNOW_PORT && destination_port != WN_ESPNOW_PORT))
        return;
    struct pbuf *p = pbuf_alloc(PBUF_RAW, size, PBUF_RAM);
    if (p && (pbuf_take(p, bytes, size) != ERR_OK || tcpip_input(p, &interface) != ERR_OK))
        pbuf_free(p);
}

void wn_espnow_poll(const char *tenant, const char *device, bool accepting,
                   struct wn_selection *selection, int64_t now)
{
    if (listener < 0)
        return;
    struct wn_ble_scope scope;
    uint8_t uuid[16];
    if (wn_ble_default_scope_init(&scope, tenant) || wn_uuid_parse(device, uuid))
        return;
    struct frame packet;
    for (unsigned i = 0; i < QUEUE_DEPTH && xQueueReceive(rx, &packet, 0) == pdTRUE; i++) {
        if (packet.generation != running_generation || !memcmp(packet.mac, station, 6))
            continue;
        if (packet.bytes[4] == IPV6) {
            deliver_ip(&packet, accepting);
        } else if (!memcmp(packet.bytes + HEADER_SIZE, scope.network_hash, 2) &&
                   !memcmp(packet.bytes + HEADER_SIZE + 2, scope.tenant_wire, 16) &&
                   packet.bytes[AD_SIZE - 1] == 1) {
            struct wn_candidate hint = {.medium = WN_ESPNOW, .port = WN_ESPNOW_PORT,
                                        .cost = WN_ESPNOW_COST};
            uint8_t address[16];
            address_from_mac(address, packet.mac);
            wn_uuid_format(packet.bytes + HEADER_SIZE + 18, hint.device);
            inet_ntop(AF_INET6, address, hint.address, sizeof hint.address);
            wn_candidate_seen(selection, &hint, now / 1000);
        }
    }
    if (radio_paused || atomic_load(&transmitting))
        return;
    if (now >= advertise_at) {
        advertise_at = now + 900000 + esp_random() % 200001;
        memcpy(packet.mac, broadcast, 6);
        memcpy(packet.bytes, prefix, sizeof prefix);
        packet.bytes[4] = PRESENCE;
        memcpy(packet.bytes + HEADER_SIZE, scope.network_hash, 2);
        memcpy(packet.bytes + HEADER_SIZE + 2, scope.tenant_wire, 16);
        memcpy(packet.bytes + HEADER_SIZE + 18, uuid, 16);
        packet.bytes[AD_SIZE - 1] = accepting;
        packet.size = AD_SIZE;
        packet.generation = running_generation;
    } else if (xQueueReceive(tx, &packet, 0) != pdTRUE) {
        return;
    }
    if (packet.generation != running_generation)
        return;
    send_deadline = now + INT64_C(2000000);
    atomic_store(&transmitting, true);
    if (radio_send(&packet) != ESP_OK)
        atomic_store(&transmitting, false);
}
#else
bool wn_espnow_supported(void) { return false; }
unsigned wn_espnow_rate_limit(unsigned configured) { (void)configured; return 1; }
void wn_espnow_set_link_rate(const void *link, const char *address, unsigned rate)
{ (void)link; (void)address; (void)rate; }
void wn_espnow_clear_link_rate(const void *link) { (void)link; }
esp_err_t wn_espnow_start(unsigned channel) { (void)channel; return ESP_ERR_NOT_SUPPORTED; }
void wn_espnow_stop(void) {}
bool wn_espnow_channel_live(unsigned channel) { (void)channel; return false; }
int wn_espnow_listener(void) { return -1; }
int wn_espnow_accept(struct wn_candidate *candidate) { (void)candidate; return -1; }
int wn_espnow_connect(const struct wn_candidate *candidate, bool *connecting)
{ (void)candidate; (void)connecting; return -1; }
void wn_espnow_poll(const char *tenant, const char *device, bool accepting,
                   struct wn_selection *selection, int64_t now)
{ (void)tenant; (void)device; (void)accepting; (void)selection; (void)now; }
#endif
