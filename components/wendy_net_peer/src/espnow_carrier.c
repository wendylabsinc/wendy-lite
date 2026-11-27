#include "espnow_carrier.h"
#include "actor_driver.h"
#include "wendy_net_espnow_hosted.h"
#include "wendy_net_ble_protocol.h"
#include "wendy_net_alloc.h"
#include "wendy_wifi.h"
#include "wendy_net_task.h"

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/idf_additions.h"
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
/* Larger data queues live in PSRAM. Keep the constrained profile's small
 * actor-driven queues, including its original internal memory requirement. */
enum { WORKER_QUEUE_DEPTH = 24, WORKER_RX_BUDGET = 8, SEND_TIMEOUT_MS = 2000 };
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
static portMUX_TYPE rate_lock = portMUX_INITIALIZER_UNLOCKED;
static QueueHandle_t rx, tx, data_rx, advertisements;
static TaskHandle_t worker;
static wendy_net_memory_reservation_t data_queue_memory, advertise_queue_memory;
static atomic_uint generation, producers, send_deadline_ms;
static atomic_bool worker_stop, worker_stopped, radio_paused, accepting_connections;
static unsigned running_generation, interface_index;
static int listener = -1;
static bool backend_started;
static int64_t advertise_at;

static void run_radio(void *context);

/* Callbacks and lwIP output can race a carrier restart. Hold a reference to
 * the current queue generation until their last queue or task access. */
static unsigned acquire_generation(void)
{
    unsigned current = atomic_load(&generation);
    if (!(current & 1u))
        return 0;
    atomic_fetch_add(&producers, 1);
    if (current == atomic_load(&generation))
        return current;
    atomic_fetch_sub(&producers, 1);
    return 0;
}

static void release_generation(void)
{
    atomic_fetch_sub(&producers, 1);
}

static void wake_data_path(void)
{
    if (worker)
        xTaskNotifyGive(worker);
    else
        wnad_wake();
}

static uint32_t send_timeout_at(int64_t now)
{
    uint32_t deadline = (uint32_t)(now / 1000) + SEND_TIMEOUT_MS;
    return deadline ? deadline : 1;
}

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
    portENTER_CRITICAL(&rate_lock);
    for (unsigned i = 0; i < CONFIG_WENDY_NET_MAX_LINKS; i++) {
        if (!link_rates[i].link || link_rates[i].link == link) {
            link_rates[i].link = link;
            memcpy(link_rates[i].mac, mac, sizeof mac);
            link_rates[i].rate = (uint8_t)rate;
            break;
        }
    }
    portEXIT_CRITICAL(&rate_lock);
}

void wn_espnow_clear_link_rate(const void *link)
{
    portENTER_CRITICAL(&rate_lock);
    for (unsigned i = 0; i < CONFIG_WENDY_NET_MAX_LINKS; i++)
        if (link_rates[i].link == link)
            link_rates[i].link = NULL;
    portEXIT_CRITICAL(&rate_lock);
}

static unsigned rate_for(const uint8_t mac[6])
{
    unsigned rate = 0;
    portENTER_CRITICAL(&rate_lock);
    for (unsigned i = 0; i < CONFIG_WENDY_NET_MAX_LINKS; i++)
        if (link_rates[i].link && !memcmp(link_rates[i].mac, mac, 6) &&
            (!rate || link_rates[i].rate < rate))
            rate = link_rates[i].rate;
    portEXIT_CRITICAL(&rate_lock);
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
    if (!bcast && worker) {
        if (xQueueSend(data_rx, &packet, 0) == pdTRUE)
            wake_data_path();
    } else if (xQueueSend(rx, &packet, 0) == pdTRUE) {
        wnad_wake();
    }
}

static void queue_received(const uint8_t source[6], const uint8_t destination[6],
                           const uint8_t *bytes, size_t size)
{
    unsigned current = acquire_generation();
    if (!current)
        return;
    enqueue_received(source, destination, bytes, size, current);
    release_generation();
}

static void completed_send(void)
{
    if (!acquire_generation())
        return;
    atomic_store(&send_deadline_ms, 0);
    wake_data_path();
    release_generation();
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
    if (p->tot_len > IP_MTU ||
        !mac_from_address(packet.mac, (const uint8_t *)destination->addr))
        return ERR_RTE;
    memcpy(packet.bytes, prefix, sizeof prefix);
    packet.bytes[4] = IPV6;
    if (pbuf_copy_partial(p, packet.bytes + HEADER_SIZE, p->tot_len, 0) != p->tot_len)
        return ERR_BUF;
    packet.size = HEADER_SIZE + p->tot_len;
    packet.generation = acquire_generation();
    if (!packet.generation)
        return ERR_RTE;
    bool queued = xQueueSend(tx, &packet, 0) == pdTRUE;
    if (queued)
        wake_data_path();
    release_generation();
    return queued ? ERR_OK : ERR_MEM;
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

bool wn_espnow_worker_active(void)
{
    return worker && listener >= 0;
}

unsigned wn_espnow_rate_limit(unsigned configured)
{
#if CONFIG_IDF_TARGET_ESP32P4
    if (!atomic_load(&hosted_rate_capable))
        return 1;
#endif
    return wn_espnow_rate_valid(configured) ? configured : 1;
}

static void release_worker_queues(void)
{
    if (tx)
        vQueueDeleteWithCaps(tx);
    if (data_rx)
        vQueueDeleteWithCaps(data_rx);
    if (advertisements)
        vQueueDelete(advertisements);
    tx = data_rx = advertisements = NULL;
    wendy_net_memory_release(&data_queue_memory);
    wendy_net_memory_release(&advertise_queue_memory);
}

static bool start_queues(void)
{
    rx = xQueueCreate(QUEUE_DEPTH, sizeof(struct frame));
    if (!rx)
        return false;
    bool can_move_io = true;
#if CONFIG_WENDY_NET_CONSTRAINED_PROFILE
    can_move_io = false;
#endif
    if (can_move_io && heap_caps_get_total_size(MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT)) {
        wendy_net_memory_t *ledger = wendy_net_runtime_memory_ledger();
        size_t data_bytes = 2 * (sizeof(StaticQueue_t) + WORKER_QUEUE_DEPTH * sizeof(struct frame));
        if (wendy_net_memory_reserve(ledger, &data_queue_memory, data_bytes,
                                     WENDY_NET_MEMORY_EXTERNAL) &&
            wendy_net_memory_reserve(ledger, &advertise_queue_memory,
                                     sizeof(StaticQueue_t) + sizeof(struct frame),
                                     WENDY_NET_MEMORY_INTERNAL)) {
            unsigned caps = MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT;
            tx = xQueueCreateWithCaps(WORKER_QUEUE_DEPTH, sizeof(struct frame), caps);
            data_rx = xQueueCreateWithCaps(WORKER_QUEUE_DEPTH, sizeof(struct frame), caps);
            advertisements = xQueueCreate(1, sizeof(struct frame));
            atomic_store(&worker_stop, false);
            atomic_store(&worker_stopped, false);
            if (tx && data_rx && advertisements &&
                wendy_net_task_create(run_radio, "espnow-io", 6144, NULL, 7, &worker) == pdPASS) {
                ESP_LOGI("wendy_espnow", "Data worker started");
                return true;
            }
        }
        release_worker_queues();
        ESP_LOGW("wendy_espnow", "Data worker unavailable, using the small actor queues");
    }
    tx = xQueueCreate(QUEUE_DEPTH, sizeof(struct frame));
    return tx != NULL;
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
    if (!start_queues()) {
        err = ESP_ERR_NO_MEM;
        goto fail;
    }
    atomic_store(&send_deadline_ms, 0);
    atomic_store(&radio_paused, false);
    atomic_store(&accepting_connections, false);
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
    advertise_at = esp_random() % 1000000;
    running_generation = atomic_fetch_add(&generation, 1) + 1;
    return ESP_OK;

fail:
    wn_espnow_stop();
    return err;
}

void wn_espnow_stop(void)
{
    if (running_generation) {
        atomic_fetch_add(&generation, 1);
        running_generation = 0;
    }
    while (atomic_load(&producers))
        vTaskDelay(1);
    bool had_worker = worker != NULL;
    if (had_worker) {
        atomic_store(&worker_stop, true);
        xTaskNotifyGive(worker);
        while (!atomic_load(&worker_stopped))
            vTaskDelay(1);
        wendy_net_task_delete(worker);
        worker = NULL;
    }
    memset(link_rates, 0, sizeof link_rates);
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
    atomic_store(&send_deadline_ms, 0);
    if (rx)
        vQueueDelete(rx);
    if (had_worker)
        release_worker_queues();
    else if (tx)
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
    bool paused = state != WENDY_WIFI_ESPNOW_READY;
    bool was_paused = atomic_exchange(&radio_paused, paused);
    unsigned deadline = atomic_load(&send_deadline_ms);
    if (state == WENDY_WIFI_ESPNOW_SCANNING) {
        /* Keep TCP live through the off-channel dwell. A concurrent send
         * completion clears the deadline and takes precedence. */
        if (deadline)
            (void)atomic_compare_exchange_strong(&send_deadline_ms, &deadline,
                                                 send_timeout_at(now));
        return true;
    }
    if (was_paused && !paused && worker)
        wake_data_path();
    return !paused && (!deadline || (int32_t)(deadline - (uint32_t)(now / 1000)) > 0);
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

static bool submit_frame(const struct frame *packet, unsigned current, int64_t now)
{
    if (packet->generation != current || atomic_load(&generation) != current ||
        atomic_load(&radio_paused))
        return false;
    atomic_store(&send_deadline_ms, send_timeout_at(now));
    if (radio_send(packet) == ESP_OK)
        return true;
    atomic_store(&send_deadline_ms, 0);
    return false;
}

static void run_radio(void *context)
{
    (void)context;
    for (;;) {
        ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
        if (atomic_load(&worker_stop))
            break;
        unsigned current = atomic_load(&generation);
        if (!(current & 1u))
            continue;
        struct frame packet;
        for (unsigned i = 0; i < WORKER_RX_BUDGET &&
             atomic_load(&generation) == current && xQueueReceive(data_rx, &packet, 0) == pdTRUE;
             ++i) {
            if (packet.generation == current && memcmp(packet.mac, station, 6))
                deliver_ip(&packet, atomic_load(&accepting_connections));
        }
        if (!atomic_load(&radio_paused) && !atomic_load(&send_deadline_ms) &&
            (xQueueReceive(advertisements, &packet, 0) == pdTRUE ||
             xQueueReceive(tx, &packet, 0) == pdTRUE) &&
            !submit_frame(&packet, current, esp_timer_get_time()) && uxQueueMessagesWaiting(tx))
            xTaskNotifyGive(xTaskGetCurrentTaskHandle());
        if (uxQueueMessagesWaiting(data_rx)) {
            xTaskNotifyGive(xTaskGetCurrentTaskHandle());
            vTaskDelay(1);
        }
    }
    /* The actor can now tear down the radio, netif and queues. No code below
     * uses any session-owned state, even if task reaping runs later. */
    atomic_store(&worker_stopped, true);
    vTaskSuspend(NULL);
}

static bool discovery_identity(struct wn_ble_scope *scope, uint8_t uuid[16],
                               const char *tenant, const char *device)
{
    static struct {
        char tenant[37], device[65];
        struct wn_ble_scope scope;
        uint8_t uuid[16];
        bool valid;
    } cache;
    if (!wn_espnow_worker_active())
        return !wn_ble_default_scope_init(scope, tenant) && !wn_uuid_parse(device, uuid);
    if (!cache.valid || strcmp(cache.tenant, tenant) || strcmp(cache.device, device)) {
        cache.valid = !wn_ble_default_scope_init(&cache.scope, tenant) &&
                      !wn_uuid_parse(device, cache.uuid);
        if (!cache.valid)
            return false;
        strlcpy(cache.tenant, tenant, sizeof cache.tenant);
        strlcpy(cache.device, device, sizeof cache.device);
    }
    *scope = cache.scope;
    memcpy(uuid, cache.uuid, sizeof cache.uuid);
    return true;
}

void wn_espnow_poll(const char *tenant, const char *device, bool accepting,
                   struct wn_selection *selection, int64_t now)
{
    if (listener < 0)
        return;
    atomic_store(&accepting_connections, accepting);
    struct wn_ble_scope scope;
    uint8_t uuid[16];
    if (!discovery_identity(&scope, uuid, tenant, device))
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
    if (atomic_load(&radio_paused) || (!worker && atomic_load(&send_deadline_ms)))
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
        if (worker) {
            xQueueOverwrite(advertisements, &packet);
            wake_data_path();
            return;
        }
    } else if (worker || xQueueReceive(tx, &packet, 0) != pdTRUE) {
        return;
    }
    (void)submit_frame(&packet, running_generation, now);
}
#else
bool wn_espnow_supported(void) { return false; }
bool wn_espnow_worker_active(void) { return false; }
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
