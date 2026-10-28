#if ESP_PLATFORM
#include "sdkconfig.h"
#endif
#include "wendy_com_service.h"
#include "wendy_server.h"
#include "wendy_server_tls.h"
#include "wendy_conf.h"
#include "wendy_pki.h"
#if CONFIG_WENDY_NET_PEER
#include "wendy_net_peer.h"
#include "wendy_net_agent.h"
#include "wendy_pki_work.h"
#include "wendy_pki_mesh.h"
#include "wendy_net_alloc.h"
#include "wendy_server_mesh.h"
#include "wendy_server_pending.h"
#include "esp_timer.h"
#include <stdatomic.h>
#endif
#include "wendy_com_link.h"
#include "esp_tls.h"
#include "mbedtls/x509_crt.h"
#include "esp_log.h"
#include "mdns.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


//--- literals ---//

#define WENDY_SERVER_DUMP_CERT    0

#define TAG                       "wendy_server"
#define WENDY_SERVER_PORT         5054
#define WENDY_SERVER_BACKLOG      4
#define WENDY_SERVER_TASK_STACK   CONFIG_WENDY_SERVER_TASK_STACK_SIZE
#define WENDY_SERVER_MAX_LINKS    4


//--- types ---//

struct _add_link_op {
    struct wcom_operation base;
    esp_tls_t *tls;
    wendy_pki_connection *pki;
    bool mesh;
};

struct wendy_server_link {
    esp_tls_t *tls;
    wendy_pki_connection *pki;
    int link_id;
    bool mesh;
};


//--- globals ---//

static struct wendy_server_link _links[WENDY_SERVER_MAX_LINKS];
static struct wendy_server_caps _caps = { .sensor_link = false };
static bool _running = false;
#if CONFIG_WENDY_NET_PEER && CONFIG_WENDY_PKI
static atomic_uint _mesh_link_count;
static atomic_bool _mesh_sweep_pending;
static bool _mesh_accepting(void)
{
    wendy_net_memory_snapshot_t state;
    wendy_net_runtime_memory_snapshot(&state);
    return state.accepting;
}
#endif


//--- internal functions ---//

#if CONFIG_WENDY_PKI
static enum wcom_link_permission _peer_permission(enum wendy_peer_role role)
{
    switch (role) {
    case WENDY_PEER_ROLE_OPERATOR:
        return WCOM_LINK_PERMISSION_FULL;
    case WENDY_PEER_ROLE_DEVICE:
        return WCOM_LINK_PERMISSION_SENSOR_ONLY;
    default:
        return WCOM_LINK_PERMISSION_NONE;
    }
}

static const struct wcom_stream_ops pki_ops = {
    .read = wendy_pki_read, .write = wendy_pki_write, .wakeup_fd = wendy_pki_fd,
};

/* Called only on the com owner thread, after any synchronous TLS/CPU call has
 * returned. Actor/crypto loans never own these management connections. */
static void _remove_pki_link(unsigned slot)
{
    struct wendy_server_link *link=&_links[slot];
    wendy_pki_connection *connection=link->pki;
    wcom_remove_link(link->link_id);
#if CONFIG_WENDY_NET_PEER
    if(link->mesh)atomic_fetch_sub(&_mesh_link_count,1);
#endif
    link->pki=NULL;link->link_id=0;link->mesh=false;
    wendy_pki_close(connection);
}
#if CONFIG_WENDY_NET_PEER
static void _mesh_sweep_exec(struct wcom_operation *unused)
{
    (void)unused;
    if(!_mesh_accepting())for(unsigned i=0;i<WENDY_SERVER_MAX_LINKS;i++)
        if(_links[i].pki && _links[i].mesh)_remove_pki_link(i);
    atomic_store(&_mesh_sweep_pending,false);
}
static struct wcom_operation _mesh_sweep_op={.func=_mesh_sweep_exec};
static void _mesh_shutdown_poll(void)
{
    if(atomic_load(&_mesh_link_count) && !_mesh_accepting() &&
       !atomic_exchange(&_mesh_sweep_pending,true))wcom_core_exec(&_mesh_sweep_op);
}
#endif
#endif

static void _on_interruption(int link_id, enum wcom_interruption_reason reason)
{
    for (int i = 0; i < WENDY_SERVER_MAX_LINKS; i++) {
        if ((_links[i].tls != NULL || _links[i].pki != NULL) && _links[i].link_id == link_id) {
            ESP_LOGI(TAG, "remove link %d (reason %d)", link_id, (int)reason);
#if CONFIG_WENDY_PKI
            if (_links[i].pki) {
                _remove_pki_link((unsigned)i);
                return;
            }
#endif
            esp_tls_t *tls = _links[i].tls;
            _links[i].tls = NULL;
            _links[i].link_id = 0;
            wcom_remove_link(link_id);
            int fd = -1;
            esp_tls_get_conn_sockfd(tls, &fd);
            if (fd >= 0)
                close(fd);
            esp_tls_server_session_delete(tls);
            return;
        }
    }
}

static void _add_link_exec(struct wcom_operation *op)
{
    struct _add_link_op *aop = (struct _add_link_op *)op;

#if CONFIG_WENDY_PKI
    if (aop->pki) {
        bool retired=false;
#if CONFIG_WENDY_NET_PEER
        retired=aop->mesh && !_mesh_accepting();
#endif
        if (retired || !wendy_conf_has_enrollment() || wendy_pki_reset_in_progress()) {
            wendy_pki_close(aop->pki);
            free(aop);
            return;
        }
        for (int i = 0; i < WENDY_SERVER_MAX_LINKS; i++) {
            if (_links[i].tls || _links[i].pki) continue;
            bool routed = aop->mesh;
            int id = (routed ? wcom_add_routed_socket_link_with_permission :
                              wcom_add_socket_link_with_permission)(&pki_ops, aop->pki,
                _on_interruption, _peer_permission(wendy_pki_get_peer_role(aop->pki)));
            if (id < 0) break;
            ESP_LOGI(TAG, "authenticated agent socket: link=%d routed=%u", id, (unsigned)routed);
            _links[i].pki = aop->pki;
            _links[i].link_id = id;
            _links[i].mesh = aop->mesh;
#if CONFIG_WENDY_NET_PEER
            if(aop->mesh)atomic_fetch_add(&_mesh_link_count,1);
#endif
            free(aop);
            return;
        }
        wendy_pki_close(aop->pki);
        free(aop);
        return;
    }
#endif
    if (wendy_conf_has_enrollment() || wendy_pki_reset_in_progress()) {
        int fd = -1;
        esp_tls_get_conn_sockfd(aop->tls, &fd);
        if (fd >= 0) close(fd);
        esp_tls_server_session_delete(aop->tls);
        free(aop);
        return;
    }
    int slot = -1;
    for (int i = 0; i < WENDY_SERVER_MAX_LINKS; i++) {
        if (_links[i].tls == NULL && _links[i].pki == NULL) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        ESP_LOGE(TAG, "max local links reached, rejecting connection");
        int fd = -1;
        esp_tls_get_conn_sockfd(aop->tls, &fd);
        if (fd >= 0)
            close(fd);
        esp_tls_server_session_delete(aop->tls);
        free(aop);
        return;
    }

    int link_id = wendy_server_add_anonymous_tls_link(aop->tls, _on_interruption);
    if (link_id < 0) {
        ESP_LOGE(TAG, "LAN TLS link setup failed, rejecting connection");
        int fd = -1;
        esp_tls_get_conn_sockfd(aop->tls, &fd);
        if (fd >= 0)
            close(fd);
        esp_tls_server_session_delete(aop->tls);
        free(aop);
        return;
    }

    ESP_LOGI(TAG, "add link %d", link_id);

    _links[slot].tls = aop->tls;
    _links[slot].link_id = link_id;
    free(aop);
}

static void _server_task(void *arg)
{
    bool enrolled = wendy_conf_has_enrollment();

#if CONFIG_WENDY_NET_PEER
    int listen_fd = socket(AF_INET6, SOCK_STREAM, 0);
#else
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
#endif
    if (listen_fd < 0) {
        ESP_LOGE(TAG, "socket() failed: %d", errno);
        vTaskDelete(NULL);
        return;
    }

#if CONFIG_WENDY_NET_PEER
    if(listen_fd>=FD_SETSIZE){
        ESP_LOGE(TAG,"listener exceeds select descriptor limit");
        close(listen_fd);vTaskDelete(NULL);return;
    }
#endif
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

#if CONFIG_WENDY_NET_PEER
    /* The same authenticated WendyCom listener serves LAN IPv4 and mesh IPv6. */
    int v6_only = 0;
    if (setsockopt(listen_fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6_only, sizeof v6_only) < 0) {
        ESP_LOGE(TAG, "dual-stack listener setup failed: %d", errno);
        close(listen_fd);
        vTaskDelete(NULL);
        return;
    }
    struct sockaddr_in6 addr = {
        .sin6_family = AF_INET6,
        .sin6_addr = IN6ADDR_ANY_INIT,
        .sin6_port = htons(WENDY_SERVER_PORT),
    };
#else
    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_ANY),
        .sin_port        = htons(WENDY_SERVER_PORT),
    };
#endif

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        ESP_LOGE(TAG, "bind() failed: %d", errno);
        close(listen_fd);
        vTaskDelete(NULL);
        return;
    }

    if (listen(listen_fd, WENDY_SERVER_BACKLOG) < 0) {
        ESP_LOGE(TAG, "listen() failed: %d", errno);
        close(listen_fd);
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "listening on port %d", WENDY_SERVER_PORT);
    if (enrolled)
        ESP_LOGI(TAG, "mTLS required: same-tenant operators or devices with SensorLink-only access");
    else
        ESP_LOGI(TAG, "device is unenrolled: anonymous TLS clients are allowed");

#if !CONFIG_WENDY_NET_TEST_NO_WIFI_RADIO
    struct wcom_service description;
    if(wcom_service_snapshot(&description)==0){
        mdns_txt_item_t txt[WCOM_SERVICE_TXT_MAX];
        for(size_t i=0;i<description.count;i++)txt[i]=(mdns_txt_item_t){
            .key=description.txt[i].key,.value=description.txt[i].value};
        esp_err_t advertised=mdns_service_add(description.instance,WCOM_SERVICE_NAME,
            WCOM_SERVICE_PROTOCOL,description.port,txt,description.count);
        if(advertised!=ESP_OK)ESP_LOGE(TAG,"mDNS service add failed: %s",esp_err_to_name(advertised));
        else ESP_LOGI(TAG,"registered mDNS service %s on port%u",WCOM_SERVICE_TYPE,(unsigned)description.port);
    }

#endif /* !CONFIG_WENDY_NET_TEST_NO_WIFI_RADIO */

#if CONFIG_WENDY_NET_PEER
    wendy_pki_work_enable();
    struct wendy_server_pending pending={.fd=-1};
#endif
    for (;;) {
#if CONFIG_WENDY_NET_PEER
        (void)wendy_pki_work_poll();
        (void)wendy_pki_io_work_poll();
        /* Reuse this already allocated certificate-capable stack. The packet
         * actor continues pumping all streams while HTTPS renewal runs. */
        wendy_net_peer_maintain();
#if CONFIG_WENDY_PKI
        _mesh_shutdown_poll();
#endif
        int apps=wendy_net_app_listener();
        int clock=wendy_net_app_time_listener();
        bool management_ready=wendy_net_app_management_ready();
        fd_set reading;FD_ZERO(&reading);
        /* Always classify cheap accepted sockets. A native VIP must reach the
         * actor even when an outbound handshake owns its SRAM workspace. */
        FD_SET(listen_fd,&reading);
        if (apps>=0) FD_SET(apps,&reading);
        if (clock>=0) FD_SET(clock,&reading);
        int maximum=apps>listen_fd ? apps : listen_fd;
        if(clock>maximum)maximum=clock;
        struct timeval poll={.tv_usec=250000};
        int available=select(maximum+1,&reading,NULL,NULL,&poll);
        if (available<0) continue;
        if(available>0 && clock>=0 && FD_ISSET(clock,&reading)){
            int incoming=accept(clock,NULL,NULL);
            if(incoming>=0)wendy_pki_net_time_relay(incoming);
        }
        if (available>0 && apps>=0 && FD_ISSET(apps,&reading)) {
            int incoming=accept(apps,NULL,NULL);
            if (incoming>=0) wendy_net_app_accept(incoming);
        }
        management_ready=wendy_net_app_management_ready();
        bool expired=false;
        uint64_t deferred_deadline=pending.deadline_ms;
        int deferred=wendy_server_pending_take(&pending,management_ready,
            (uint64_t)esp_timer_get_time()/1000,&expired);
        if(expired){close(deferred);deferred=-1;}
        if(deferred<0 && (available==0 || !FD_ISSET(listen_fd,&reading)))continue;
#endif
        struct sockaddr_storage client_addr={0};
        socklen_t client_len = sizeof(client_addr);
#if CONFIG_WENDY_NET_PEER
        int client_fd=deferred>=0 ? deferred :
            accept(listen_fd,(struct sockaddr *)&client_addr,&client_len);
#else
        int client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &client_len);
#endif
        if (client_fd < 0) {
            ESP_LOGE(TAG, "accept() failed: %d", errno);
            continue;
        }

        // SensorLink sends small headers followed by payloads. Do not wait
        // for a delayed ACK before transmitting the next TLS record.
        int no_delay = 1;
        if (setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &no_delay, sizeof no_delay) < 0) {
            ESP_LOGW(TAG, "setting TCP_NODELAY failed: %d", errno);
            close(client_fd);
            continue;
        }

        // Once enrollment is configured, never fall back to anonymous TLS.
        if (wendy_conf_has_enrollment()) {
#if CONFIG_WENDY_PKI
#if CONFIG_WENDY_NET_PEER
            int classification=wendy_server_mesh_socket(client_fd);
            if(classification<0){close(client_fd);continue;}
            if(classification>0){wendy_net_agent_accept(client_fd);continue;}
            /* Baseline physical TLS still obeys the previous headroom gate.
             * Retain one raw fd, with a fixed deadline, rather than repeatedly
             * accepting/closing that client while mesh crypto is in flight. */
            if(!wendy_net_app_management_ready()){
                if(!wendy_server_pending_put(&pending,client_fd,
                    (uint64_t)esp_timer_get_time()/1000))close(client_fd);
                else if(deferred>=0)pending.deadline_ms=deferred_deadline;
                continue;
            }
            wendy_net_peer_prepare_handshake();
#endif
            struct _add_link_op *op = calloc(1, sizeof *op);
            if (!op) { close(client_fd); continue; }
#if CONFIG_WENDY_NET_PEER
            wendy_net_memory_scope_t previous=wendy_net_memory_scope_enter(NULL,WENDY_NET_MEMORY_INTERNAL);
#endif
            esp_err_t accepted=wendy_pki_accept_lan(client_fd, &op->pki);
#if CONFIG_WENDY_NET_PEER
            wendy_net_memory_scope_leave(previous);
#endif
            if (accepted != ESP_OK) {
                ESP_LOGW(TAG, "PKI LAN authentication failed");
                ESP_LOGI(TAG, "LAN worker stack free=%u",(unsigned)uxTaskGetStackHighWaterMark(NULL));
                free(op);
                continue;
            }
            ESP_LOGI(TAG, "LAN authenticated; worker stack free=%u",(unsigned)uxTaskGetStackHighWaterMark(NULL));
            op->base.func = _add_link_exec;
            wcom_core_exec(&op->base);
#else
            close(client_fd);
#endif
            continue;
        }
        // Anonymous TLS is only available before enrollment.
        struct wendy_conf_span key = wendy_conf_get_default_private_key();
        struct wendy_conf_span cert = wendy_conf_get_default_certificate();
        if (wendy_pki_reset_in_progress()) {
            ESP_LOGW(TAG, "LAN authentication unavailable during enrollment reset");
            close(client_fd);
            continue;
        }
        esp_tls_t *tls = esp_tls_init();
        if (!tls) {
            ESP_LOGE(TAG, "esp_tls_init() failed");
            close(client_fd);
            continue;
        }

        esp_tls_cfg_server_t cfg = {
            .servercert_buf   = cert.data,
            .servercert_bytes = cert.size,
            .serverkey_buf    = key.data,
            .serverkey_bytes  = key.size,
        };

#if WENDY_SERVER_DUMP_CERT == 1
        {
            mbedtls_x509_crt srv_crt;
            mbedtls_x509_crt_init(&srv_crt);
            if (mbedtls_x509_crt_parse_der(&srv_crt, cfg.servercert_buf, cfg.servercert_bytes) == 0) {
                char buf[256];
                mbedtls_x509_dn_gets(buf, sizeof(buf), &srv_crt.subject);
                ESP_LOGI(TAG, "server cert DN: %s", buf);
            }
            mbedtls_x509_crt_free(&srv_crt);
        }
#endif

        esp_err_t init_ret = esp_tls_server_session_init(&cfg, client_fd, tls);
        if (init_ret != ESP_OK) {
            ESP_LOGE(TAG, "TLS session init failed: 0x%x", init_ret);
            close(client_fd);
            esp_tls_server_session_delete(tls);
            continue;
        }

        int ret;
        while ((ret = esp_tls_server_session_continue_async(tls)) != 0) {
            if (ret != ESP_TLS_ERR_SSL_WANT_READ && ret != ESP_TLS_ERR_SSL_WANT_WRITE)
                break;
        }
        if (ret != 0) {
            ESP_LOGE(TAG, "TLS handshake failed: 0x%x", -ret);
            close(client_fd);
            esp_tls_server_session_delete(tls);
            continue;
        }

        // Enrollment or reset during the handshake invalidates anonymous access.
        if (wendy_conf_has_enrollment() || wendy_pki_reset_in_progress()) {
            ESP_LOGW(TAG, "LAN client rejected: enrollment state changed during TLS handshake");
            close(client_fd);
            esp_tls_server_session_delete(tls);
            continue;
        }

        ESP_LOGI(TAG, "accepted TLS connection (address family %d)", client_addr.ss_family);

        struct _add_link_op *op = calloc(1, sizeof(*op));
        if (!op) {
            ESP_LOGE(TAG, "malloc failed");
            close(client_fd);
            esp_tls_server_session_delete(tls);
            continue;
        }
        op->base.func = _add_link_exec;
        op->tls = tls;
        wcom_core_exec(&op->base);
    }
}


//--- public functions ---//

void wendy_server_set_caps(const struct wendy_server_caps caps)
{
    assert(!_running);
    _caps = caps;
}

void wendy_server_start(void)
{
    _running = true;
    xTaskCreatePinnedToCore(_server_task, "wendy_server", WENDY_SERVER_TASK_STACK, NULL,
                             CONFIG_WENDY_SERVER_TASK_PRIORITY, NULL,
                             CONFIG_WENDY_SERVER_TASK_CORE_AFFINITY);
}

void wendy_server_accept_operator(int fd, const struct wendy_lite_trust *trust)
{
#if CONFIG_WENDY_PKI
    struct _add_link_op *op = calloc(1, sizeof *op);
    if (!op) { close(fd); return; }
#if CONFIG_WENDY_NET_PEER
    wendy_net_peer_prepare_handshake();
#endif
    if (wendy_pki_accept_relay(fd, trust, &op->pki) != ESP_OK) {
        ESP_LOGW(TAG, "cloud operator session rejected");
        free(op);
        return;
    }
    op->base.func = _add_link_exec;
    wcom_core_exec(&op->base);
#else
    (void)trust;
    close(fd);
#endif
}
