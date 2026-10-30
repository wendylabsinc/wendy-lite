#include "wendy_ble.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_system.h"


//--- globals ---//

static const char *TAG = "wendy_ble";
#ifndef CONFIG_WENDY_NET_BLE
#define CONFIG_WENDY_NET_BLE 0
#endif
#if CONFIG_WENDY_NET_BLE
#include "wendy_net_profile.h"
#endif


#if CONFIG_WENDY_BLE

#include "wendy_conf.h"
#include "wendy_pki.h"
#if CONFIG_WENDY_NET_PEER
#include "wendy_pki_work.h"
#endif
#include "wendy_ble_l2cap.h"
#include "wendy_ble_tls.h"
#include "wendy_com_link.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "host/ble_gap.h"
#if CONFIG_BT_NIMBLE_EXT_ADV
#include "host/ble_hs_adv.h"
#include "host/ble_hs_mbuf.h"
#endif
#include "host/ble_uuid.h"
#include "host/util/util.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"
#if CONFIG_WENDY_NET_BLE
#include "wendy_ble_mesh.h"
#include "esp_timer.h"
#include <stdatomic.h>
static uint8_t _mesh_advertisement[31];
static size_t _mesh_advertisement_size;
static bool _mesh_turn;
static portMUX_TYPE _mesh_adv_lock=portMUX_INITIALIZER_UNLOCKED;
static atomic_bool _mesh_configuring;
static esp_timer_handle_t _mesh_adv_timer;
static struct ble_npl_event _mesh_adv_event;
/* Incoming advertising GAPs belong to this host, even when a new CoC is
 * refused. No application channel means a bounded idle selection lease. */
struct incoming_gap { int64_t idle_until; uint16_t handle; bool used, terminating; };
static struct incoming_gap _incoming_gaps[CONFIG_BT_NIMBLE_MAX_CONNECTIONS];
static void _incoming_touch(uint16_t handle)
{
    for(size_t i=0;i<sizeof _incoming_gaps/sizeof *_incoming_gaps;i++)
        if(_incoming_gaps[i].used && _incoming_gaps[i].handle==handle)
            _incoming_gaps[i].idle_until=esp_timer_get_time()+INT64_C(30000000);
}
static void _incoming_connect(uint16_t handle)
{
    struct ble_gap_conn_desc desc;
    if(ble_gap_conn_find(handle,&desc) || desc.role!=BLE_GAP_ROLE_SLAVE)return;
    for(size_t i=0;i<sizeof _incoming_gaps/sizeof *_incoming_gaps;i++)
        if(!_incoming_gaps[i].used || _incoming_gaps[i].handle==handle){
            _incoming_gaps[i]=(struct incoming_gap){.used=true,.handle=handle,
                .idle_until=esp_timer_get_time()+INT64_C(30000000)};
            ESP_LOGI(TAG,"incoming GAP lease: handle=%u peer=%02x:%02x:%02x:%02x:%02x:%02x",
                handle,desc.peer_id_addr.val[5],desc.peer_id_addr.val[4],
                desc.peer_id_addr.val[3],desc.peer_id_addr.val[2],
                desc.peer_id_addr.val[1],desc.peer_id_addr.val[0]);
            return;
        }
}
static void _incoming_disconnect(uint16_t handle)
{
    for(size_t i=0;i<sizeof _incoming_gaps/sizeof *_incoming_gaps;i++)
        if(_incoming_gaps[i].used && _incoming_gaps[i].handle==handle)
            _incoming_gaps[i]=(struct incoming_gap){0};
}
static void _incoming_retire(void)
{
    int64_t now=esp_timer_get_time();
    for(size_t i=0;i<sizeof _incoming_gaps/sizeof *_incoming_gaps;i++){
        struct incoming_gap *g=&_incoming_gaps[i];
        if(!g->used || g->terminating || now<g->idle_until)continue;
        /* Both probes are conservative/nonblocking. Pending, active and
         * closing channels, or unknown lifetime/lock contention, keep GAP. */
        if(!wble_l2cap_connection_idle(g->handle) ||
            wble_mesh_uses_connection(g->handle))continue;
        int rc=ble_gap_terminate(g->handle,BLE_ERR_REM_USER_CONN_TERM);
        if(!rc || rc==BLE_HS_EALREADY){
            g->terminating=true;
            ESP_LOGI(TAG,"retiring idle incoming GAP: handle=%u",g->handle);
        }else if(rc==BLE_HS_ENOTCONN)*g=(struct incoming_gap){0};
        else g->idle_until=now+INT64_C(5000000);
    }
}
#endif


//--- literals ---//

#define ADV_ITVL_MIN_MS  100
#define ADV_ITVL_MAX_MS  150

#define SESSION_TASK_STACK  4096
// PKI identity verification uses the same stack budget as the LAN server.
#define PKI_SESSION_TASK_STACK  24576

// Company identifier 0xFFFF is the range the Bluetooth SIG reserves for
// internal use and testing, which is what a device ID in an advertisement is.
#define MFG_COMPANY_ID_LO  0xFF
#define MFG_COMPANY_ID_HI  0xFF

// A scan response holds 31 bytes: the name costs 2 + len, the manufacturer
// data 2 + 2 + len. The ID gets a fixed allowance (it is short and stable),
// and the name takes whatever is left.
#define SCAN_RSP_BUDGET    31
#define DEVICE_ID_ADV_MAX  12

// Leave the name at least a few bytes, and keep the budget arithmetic in
// _start_advertising() from underflowing its size_t.
_Static_assert(DEVICE_ID_ADV_MAX + 4 + 2 + 4 <= SCAN_RSP_BUDGET,
               "DEVICE_ID_ADV_MAX leaves no room for a local name");

/* Info service 4E57454E-4459-0002-000x-000000000000 — "NWENDY", service 2,
 * the same base WendyOS uses for the Wi-Fi provisioning service (0001).
 * NimBLE stores 128-bit UUIDs least significant byte first, so these read
 * backwards compared to the canonical string form. */
#define WENDY_BLE_UUID128(lo)                                             \
    BLE_UUID128_INIT(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, (lo), 0x00,      \
                     0x02, 0x00, 0x59, 0x44, 0x4E, 0x45, 0x57, 0x4E)


//--- types ---//

/* Which value a characteristic read should return. Passed through the
 * ble_gatt_chr_def arg, so it must never be 0 — that is what an absent arg
 * looks like. */
enum info_field {
    INFO_PSM = 1,
    INFO_DEVICE_ID,
    INFO_DEVICE_NAME,
    INFO_DISPLAY_NAME,
    INFO_MTLS,
    INFO_PRINCIPAL,
};


//--- globals ---//

static const ble_uuid128_t _uuid_svc          = WENDY_BLE_UUID128(0x00);
static const ble_uuid128_t _uuid_psm          = WENDY_BLE_UUID128(0x01);
static const ble_uuid128_t _uuid_device_id    = WENDY_BLE_UUID128(0x02);
static const ble_uuid128_t _uuid_device_name  = WENDY_BLE_UUID128(0x03);
static const ble_uuid128_t _uuid_display_name = WENDY_BLE_UUID128(0x04);
static const ble_uuid128_t _uuid_mtls         = WENDY_BLE_UUID128(0x05);
static const ble_uuid128_t _uuid_principal    = WENDY_BLE_UUID128(0x06);

static bool  _host_initialized;
static bool  _started;
static bool  _enrolled;
static uint8_t _own_addr_type;

static char *_device_id;
static char *_device_name;
static char *_display_name;
/* The enrolled device principal, spiffe://wendy.sh/tenant/<tenant>/device/<uuid>,
 * the same string LAN discovery publishes as TXT principal=; empty when
 * unenrolled. Its UUID is the device's one id, the pin target for mTLS. It is
 * too long for the advertisement, whose manufacturer data keeps the hardware id. */
static char _principal[160];

static uint8_t _mfg_data[2 + DEVICE_ID_ADV_MAX];
static uint8_t _mfg_data_len;


//--- internal functions ---//

static int _info_access(uint16_t conn_handle, uint16_t attr_handle,
                        struct ble_gatt_access_ctxt *ctxt, void *arg);

static const struct ble_gatt_chr_def _info_chrs[] = {
    {
        .uuid      = &_uuid_psm.u,
        .access_cb = _info_access,
        .arg       = (void *)(uintptr_t)INFO_PSM,
        .flags     = BLE_GATT_CHR_F_READ,
    },
    {
        .uuid      = &_uuid_device_id.u,
        .access_cb = _info_access,
        .arg       = (void *)(uintptr_t)INFO_DEVICE_ID,
        .flags     = BLE_GATT_CHR_F_READ,
    },
    {
        .uuid      = &_uuid_device_name.u,
        .access_cb = _info_access,
        .arg       = (void *)(uintptr_t)INFO_DEVICE_NAME,
        .flags     = BLE_GATT_CHR_F_READ,
    },
    {
        .uuid      = &_uuid_display_name.u,
        .access_cb = _info_access,
        .arg       = (void *)(uintptr_t)INFO_DISPLAY_NAME,
        .flags     = BLE_GATT_CHR_F_READ,
    },
    {
        .uuid      = &_uuid_mtls.u,
        .access_cb = _info_access,
        .arg       = (void *)(uintptr_t)INFO_MTLS,
        .flags     = BLE_GATT_CHR_F_READ,
    },
    {
        .uuid      = &_uuid_principal.u,
        .access_cb = _info_access,
        .arg       = (void *)(uintptr_t)INFO_PRINCIPAL,
        .flags     = BLE_GATT_CHR_F_READ,
    },
    { 0 },
};

static const struct ble_gatt_svc_def _gatt_svcs[] = {
    {
        .type            = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid            = &_uuid_svc.u,
        .characteristics = _info_chrs,
    },
    { 0 },
};

static int _info_access(uint16_t conn_handle, uint16_t attr_handle,
                        struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    (void)attr_handle;

    if (ctxt->op != BLE_GATT_ACCESS_OP_READ_CHR)
        return BLE_ATT_ERR_UNLIKELY;

#if CONFIG_WENDY_NET_BLE
    _incoming_touch(conn_handle);
#else
    (void)conn_handle;
#endif
    // Both are little-endian on the wire, which is also the native byte order
    // on every target this builds for.
    uint16_t psm  = CONFIG_WENDY_BLE_PSM;
    uint8_t  mtls = _enrolled ? 1 : 0;

    const void *data;
    uint16_t len;

    switch ((enum info_field)(uintptr_t)arg) {
        case INFO_PSM:
            data = &psm;
            len = sizeof(psm);
            break;
        case INFO_DEVICE_ID:
            data = _device_id ? _device_id : "";
            len = (uint16_t)strlen(data);
            break;
        case INFO_DEVICE_NAME:
            data = _device_name ? _device_name : "";
            len = (uint16_t)strlen(data);
            break;
        case INFO_DISPLAY_NAME:
            data = _display_name ? _display_name : "";
            len = (uint16_t)strlen(data);
            break;
        case INFO_MTLS:
            data = &mtls;
            len = sizeof(mtls);
            break;
        case INFO_PRINCIPAL:
            data = _principal;
            len = (uint16_t)strlen(_principal);
            break;
        default:
            return BLE_ATT_ERR_UNLIKELY;
    }

    if (len == 0)
        return 0; // an empty read is a valid answer, not an error

    return os_mbuf_append(ctxt->om, data, len) == 0 ? 0
                                                    : BLE_ATT_ERR_INSUFFICIENT_RES;
}

static int _gap_event(struct ble_gap_event *event, void *arg);
static int _start_advertising(bool quiet_capacity);

#if CONFIG_BT_NIMBLE_EXT_ADV
#if CONFIG_WENDY_NET_BLE
#define _radio_profile wble_mesh_profile
#define _radio_profile_name wble_mesh_profile_name
#else
static unsigned _radio_profile(void){return 0;}
static const char *_radio_profile_name(void){return "normal";}
#endif
static bool _ext_configured;
static int _set_adv_data(const void *data,size_t size,bool response)
{
    struct os_mbuf *buffer=ble_hs_mbuf_from_flat(data,size);
    if(!buffer)return BLE_HS_ENOMEM;
    return response ? ble_gap_ext_adv_rsp_set_data(0,buffer):ble_gap_ext_adv_set_data(0,buffer);
}
#if CONFIG_WENDY_NET_BLE
static bool _advertising_active(void){return ble_gap_ext_adv_active(0);}
#endif
#elif CONFIG_WENDY_NET_BLE
static bool _advertising_active(void){return ble_gap_adv_active();}
#endif

static int _primary_advertisement(bool mesh)
{
#if CONFIG_WENDY_NET_BLE
    uint8_t bytes[31];size_t size;
    portENTER_CRITICAL(&_mesh_adv_lock);
    size=_mesh_advertisement_size;memcpy(bytes,_mesh_advertisement,size);
    portEXIT_CRITICAL(&_mesh_adv_lock);
    if(mesh && size){
#if CONFIG_BT_NIMBLE_EXT_ADV
        return _set_adv_data(bytes,size,false);
#else
        return ble_gap_adv_set_data(bytes,size);
#endif
    }
#else
    (void)mesh;
#endif
    struct ble_hs_adv_fields adv={0};
    adv.flags=BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
    adv.uuids128=&_uuid_svc;adv.num_uuids128=1;adv.uuids128_is_complete=1;
#if CONFIG_BT_NIMBLE_EXT_ADV
    uint8_t data[31],length=0;
    int rc=ble_hs_adv_set_fields(&adv,data,&length,sizeof data);
    return rc ? rc:_set_adv_data(data,length,false);
#else
    return ble_gap_adv_set_fields(&adv);
#endif
}
#if CONFIG_WENDY_NET_BLE
static void _mesh_adv_refresh(struct ble_npl_event *event)
{
    (void)event;
    portENTER_CRITICAL(&_mesh_adv_lock);
    bool enabled=_mesh_advertisement_size!=0;
    portEXIT_CRITICAL(&_mesh_adv_lock);
    if(enabled && (!_started || !_enrolled || !wendy_conf_is_current() ||
        wendy_pki_reset_in_progress()))return;
    /* A full peer can receive a mesh GAP while its outgoing GAP is still
     * retiring. A controller-capacity failure then leaves management stopped;
     * that outgoing link's disconnect belongs to a different callback. Reuse
     * this existing host event/timer to recover, with no new state or worker. */
    if(enabled)_incoming_retire();
    if(enabled && !_advertising_active()){
        _start_advertising(true);
        /* No public SDK connection-capacity count includes pending GAPs.
         * Slow stopped retries (and SDK HCI diagnostics) while capacity is
         * unavailable; successful recovery restores ordinary payload rotation. */
        esp_err_t restarted=esp_timer_restart(_mesh_adv_timer,
            _advertising_active() ? 500000:5000000);
        if(restarted!=ESP_OK)ESP_LOGW(TAG,"advertisement retry timer failed: %s",esp_err_to_name(restarted));
    }
    _mesh_turn=enabled && !_mesh_turn;
    int rc=_primary_advertisement(_mesh_turn);
    if(rc)ESP_LOGW(TAG,"primary advertisement refresh failed: %d",rc);
    if(!enabled && _mesh_adv_timer){
        esp_timer_delete(_mesh_adv_timer);_mesh_adv_timer=NULL;
        ble_npl_event_deinit(&_mesh_adv_event);
    }
}
static void _mesh_adv_tick(void *context)
{
    (void)context;
    ble_npl_eventq_put(nimble_port_get_dflt_eventq(),&_mesh_adv_event);
}
esp_err_t wendy_ble_mesh_advertisement(const uint8_t *data,size_t size)
{
    if(size>31 || (size && !data))return ESP_ERR_INVALID_ARG;
#if WENDY_NET_NON_TRANSIT
    /* Only the mesh publication is suppressed. The primary WendyCom service
     * keeps its own advertisement, GATT discovery and management listener. */
    if(size)return ESP_ERR_NOT_SUPPORTED;
#endif
    if(!size && !_mesh_adv_timer)return ESP_OK;
    if(!_started || !_enrolled || !ble_hs_synced())return ESP_ERR_INVALID_STATE;
    if(atomic_exchange(&_mesh_configuring,true))return ESP_ERR_INVALID_STATE;
    esp_err_t result=ESP_OK;
    if(!_mesh_adv_timer){
        ble_npl_event_init(&_mesh_adv_event,_mesh_adv_refresh,NULL);
        const esp_timer_create_args_t args={.callback=_mesh_adv_tick,.name="net-adv"};
        result=esp_timer_create(&args,&_mesh_adv_timer);
        if(result!=ESP_OK)goto done;
    }
    esp_timer_stop(_mesh_adv_timer);
    portENTER_CRITICAL(&_mesh_adv_lock);
    if(size)memcpy(_mesh_advertisement,data,size);
    _mesh_advertisement_size=size;
    portEXIT_CRITICAL(&_mesh_adv_lock);
    if(size)result=esp_timer_start_periodic(_mesh_adv_timer,500000);
    ble_npl_eventq_put(nimble_port_get_dflt_eventq(),&_mesh_adv_event);
done:
    atomic_store(&_mesh_configuring,false);return result;
}
bool wendy_ble_mesh_advertisement_idle(void){return _mesh_adv_timer==NULL;}
#endif

/// Advertise the service UUID in the advertisement itself so a central can
/// filter for it in-stack (CoreBluetooth's scanForPeripheralsWithServices:
/// matches on the advertisement, not the scan response), and put the identity
/// in the scan response, where there is room for it.
static int _start_advertising(bool quiet_capacity)
{
    if (wendy_pki_reset_in_progress() || wendy_conf_has_enrollment() != _enrolled ||
        (_enrolled && !wendy_conf_is_current()))
        return BLE_HS_EBUSY;

    int rc;
#if CONFIG_BT_NIMBLE_EXT_ADV
    if(!_ext_configured){
        unsigned profile=_radio_profile();
        struct ble_gap_ext_adv_params ext={.connectable=1,
            .scannable=profile==0,.legacy_pdu=profile==0,
            .own_addr_type=_own_addr_type,.primary_phy=profile ? 3:1,
            .secondary_phy=profile ? 3:1,.sid=0,
            .tx_power=wendy_ble_power_advertising_request(),
            .itvl_min=BLE_GAP_ADV_ITVL_MS(profile ? 250:ADV_ITVL_MIN_MS),
            .itvl_max=BLE_GAP_ADV_ITVL_MS(profile ? 300:ADV_ITVL_MAX_MS),
#if CONFIG_BT_NIMBLE_EXT_ADV_V2
            .primary_phy_opt=profile==1 ? 3:profile==2 ? 4:0,
            .secondary_phy_opt=profile==1 ? 3:profile==2 ? 4:0,
#endif
        };
        int8_t power=0;
        rc=ble_gap_ext_adv_configure(0,&ext,&power,_gap_event,NULL);
        ESP_LOGI(TAG,"radio advertisement profile=%s primary=%u secondary=%u required_coding=%u power=%d rc=%d",
            _radio_profile_name(),ext.primary_phy,ext.secondary_phy,profile==1 ? 3:profile==2 ? 4:0,power,rc);
        if(rc)return rc;
        wendy_ble_power_advertising_selected(power);
        _ext_configured=true;
    }
#endif
    rc = _primary_advertisement(false);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gap_adv_set_fields failed: %d", rc);
        return rc;
    }

    struct ble_hs_adv_fields rsp = {0};
    if (_mfg_data_len > 0) {
        rsp.mfg_data = _mfg_data;
        rsp.mfg_data_len = _mfg_data_len;
    }
    if (_device_name && _device_name[0]) {
        size_t name_len = strlen(_device_name);
        size_t budget = SCAN_RSP_BUDGET - 2 - (_mfg_data_len ? _mfg_data_len + 2 : 0);
        if (name_len > budget) {
            ESP_LOGW(TAG, "advertised name truncated to %u bytes", (unsigned)budget);
            name_len = budget;
        }
        rsp.name = (const uint8_t *)_device_name;
        rsp.name_len = (uint8_t)name_len;
        rsp.name_is_complete = (name_len == strlen(_device_name));
    }

#if CONFIG_BT_NIMBLE_EXT_ADV
    /* Connectable extended advertisements cannot be scannable. The GATT
     * identity remains available; legacy normal mode retains scan response. */
    if(!_radio_profile()){
        uint8_t bytes[31],size=0;
        rc=ble_hs_adv_set_fields(&rsp,bytes,&size,sizeof bytes);
        if(!rc)rc=_set_adv_data(bytes,size,true);
    }else rc=0;
#else
    rc = ble_gap_adv_rsp_set_fields(&rsp);
#endif
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gap_adv_rsp_set_fields failed: %d", rc);
        return rc;
    }

#if CONFIG_BT_NIMBLE_EXT_ADV
    rc=ble_gap_ext_adv_start(0,0,0);
#else
    rc=wendy_ble_power_apply_advertising();
    if(rc)return rc;
    struct ble_gap_adv_params params = {
        .conn_mode = BLE_GAP_CONN_MODE_UND,
        .disc_mode = BLE_GAP_DISC_MODE_GEN,
        .itvl_min  = BLE_GAP_ADV_ITVL_MS(ADV_ITVL_MIN_MS),
        .itvl_max  = BLE_GAP_ADV_ITVL_MS(ADV_ITVL_MAX_MS),
    };

    rc = ble_gap_adv_start(_own_addr_type, NULL, BLE_HS_FOREVER,
                           &params, _gap_event, NULL);
#endif
    if (rc != 0 && rc != BLE_HS_EALREADY) {
        if(!quiet_capacity || (rc!=BLE_HS_ENOMEM && rc!=BLE_HS_HCI_ERR(BLE_ERR_MEM_CAPACITY)))
            ESP_LOGE(TAG, "ble_gap_adv_start failed: %d", rc);
        return rc;
    }

    wendy_ble_power_advertising_started();
    ESP_LOGI(TAG, "advertising as '%s' (id '%s')",
             _device_name ? _device_name : "",
             _device_id ? _device_id : "");
    return 0;
}

static int _gap_event(struct ble_gap_event *event, void *arg)
{
    (void)arg;

#if CONFIG_WENDY_NET_BLE
    wble_mesh_profile_event(event);
#endif
    switch (event->type) {
        case BLE_GAP_EVENT_CONNECT:
            ESP_LOGI(TAG, "connect: status=%d handle=%d",
                     event->connect.status, event->connect.conn_handle);
#if CONFIG_WENDY_NET_BLE
            if(!event->connect.status){_incoming_connect(event->connect.conn_handle);wble_mesh_profile_connected(event->connect.conn_handle);}
#endif
            // A failed connect leaves advertising stopped; a successful one is
            // undirected connectable, so it stops too.
            if (event->connect.status != 0 || CONFIG_WENDY_NET_BLE)
                _start_advertising(false);
            break;

        case BLE_GAP_EVENT_DISCONNECT:
            ESP_LOGI(TAG, "disconnect: reason=%d", event->disconnect.reason);
#if CONFIG_WENDY_NET_BLE
            _incoming_disconnect(event->disconnect.conn.conn_handle);
#endif
            _start_advertising(false);
            break;

        case BLE_GAP_EVENT_ADV_COMPLETE:
            _start_advertising(false);
            break;

        case BLE_GAP_EVENT_MTU:
            ESP_LOGD(TAG, "ATT MTU now %d", event->mtu.value);
            break;

        default:
            break;
    }
    return 0;
}

static void _on_sync(void)
{
    int rc = ble_hs_util_ensure_addr(0);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_hs_util_ensure_addr failed: %d", rc);
        return;
    }
    rc = ble_hs_id_infer_auto(0, &_own_addr_type);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_hs_id_infer_auto failed: %d", rc);
        return;
    }

    rc=wendy_ble_power_host_sync();
    if(rc)ESP_LOGE(TAG,"Bluetooth power unavailable: %d",rc);
#if CONFIG_WENDY_NET_BLE
    rc=wble_mesh_profile_sync();
    if(rc){ESP_LOGE(TAG,"BLE profile unavailable: %d",rc);return;}
#endif
    ESP_LOGI(TAG, "BLE host synced");

    if (_started)
        _start_advertising(false);
}

static void _on_reset(int reason)
{
    ESP_LOGW(TAG, "BLE host reset: reason=%d", reason);
    wendy_ble_power_host_reset();
#if CONFIG_WENDY_NET_BLE
    memset(_incoming_gaps,0,sizeof _incoming_gaps);
#endif
#if CONFIG_BT_NIMBLE_EXT_ADV
    _ext_configured=false;
#endif
}

static void _host_task(void *param)
{
    (void)param;
    nimble_port_run();
    nimble_port_freertos_deinit();
}

/// Bringing the stack up costs tens of KiB on a chip that is already tight
/// with WiFi and the WAMR pool resident, and a shortfall shows up much later
/// as mbedtls_ssl_setup returning ALLOC_FAILED. Log both numbers so the cost
/// is visible in the boot log rather than inferred from a failure.
static void _log_heap(const char *when)
{
    ESP_LOGI(TAG, "heap %s BLE init: free=%u largest_block=%u",
             when,
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT),
             (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
}

/// The scan response carries the compact hardware ID. The GATT identity
/// characteristic carries the full enrolled PKI ID used for TLS pinning.
static void _build_mfg_data(void)
{
    _mfg_data_len = 0;
    const char *hardware_id = wendy_conf_get_device_id();
    if (!hardware_id || !hardware_id[0])
        return;

    size_t id_len = strlen(hardware_id);
    if (id_len > DEVICE_ID_ADV_MAX) {
        // Truncating would put a wrong ID on the air, and a wrong ID is worse
        // than no device: a scan would show an identity that matches nothing.
        // The ID is a build-time property of the firmware, not something a
        // user can get wrong at runtime, so refusing to boot is the fastest
        // way to surface it.
        ESP_LOGE(TAG, "device id '%s' is %u bytes, more than the %d that fit "
                      "in the advertisement",
                 hardware_id, (unsigned)id_len, DEVICE_ID_ADV_MAX);
        esp_system_abort("wendy_ble: device id too long to advertise");
    }

    _mfg_data[0] = MFG_COMPANY_ID_LO;
    _mfg_data[1] = MFG_COMPANY_ID_HI;
    memcpy(&_mfg_data[2], hardware_id, id_len);
    _mfg_data_len = (uint8_t)(2 + id_len);
}


/* ── Session task ───────────────────────────────────────────────────────
 *
 * Waits for a peer to open the channel, runs the TLS handshake, then hands
 * the encrypted stream to the wcom task and waits for the link to die.
 *
 * Ownership rule: exactly one task touches the TLS context at a time.
 * This task owns it up to wcom_core_exec(); the wcom task owns it from when
 * that operation runs until the link is removed (which also happens on the
 * wcom task); ownership comes back here only once _link_closed is signalled.
 */

static SemaphoreHandle_t _link_closed;

/* Com-owner-only receipt state for the one physical management session. A
 * successful TLS write may leave its last SDU stalled inside NimBLE. */
static uint32_t _reply_token;
static void (*_reply_done)(uint32_t);
static void _complete_reply(void)
{
    uint32_t token=_reply_token;_reply_token=0;
    if(token)_reply_done(token);
}
static void _poll_reply(void)
{
    if(_reply_token && wble_l2cap_can_write())_complete_reply();
}
static void _stream_reply_barrier(void *context,uint32_t token,void (*done)(uint32_t))
{
    (void)context;
    _complete_reply(); /* Superseded/timed-out configuration; one bounded slot. */
    _reply_done=done;_reply_token=token;_poll_reply();
}

static ssize_t _stream_read(void *ctx, void *buf, size_t len)
{
    (void)ctx;
    ssize_t n = wble_tls_read(buf, len);
    switch (n) {
        case WBLE_ERR_WANT_READ:  return WCOM_STREAM_ERR_WANT_READ;
        case WBLE_ERR_WANT_WRITE: return WCOM_STREAM_ERR_WANT_WRITE;
        case WBLE_ERR_UNKNOWN:    return WCOM_STREAM_ERR_UNKNOWN;
        default:                  return n;
    }
}

static ssize_t _stream_write(void *ctx, const void *buf, size_t len)
{
    (void)ctx;
    ssize_t n = wble_tls_write(buf, len);
    switch (n) {
        case WBLE_ERR_WANT_READ:  return WCOM_STREAM_ERR_WANT_READ;
        case WBLE_ERR_WANT_WRITE: return WCOM_STREAM_ERR_WANT_WRITE;
        case WBLE_ERR_UNKNOWN:    return WCOM_STREAM_ERR_UNKNOWN;
        default:                  return n;
    }
}

static int _stream_wakeup_fd(void *ctx)
{
    (void)ctx;
    return wble_l2cap_wakeup_fd();
}

static bool _stream_can_read(void *ctx)
{
    (void)ctx;
    _poll_reply();
    // Decrypted bytes already inside TLS count as readable: no transport
    // event is coming to announce them.
    return wble_tls_pending() || wble_l2cap_can_read();
}

static bool _stream_can_write(void *ctx)
{
    (void)ctx;
    _poll_reply();
    return wble_l2cap_can_write();
}

static const struct wcom_stream_ops _stream_ops = {
    .read      = _stream_read,
    .write     = _stream_write,
    .wakeup_fd = _stream_wakeup_fd,
    .can_read  = _stream_can_read,
    .can_write = _stream_can_write,
    .reply_barrier = _stream_reply_barrier,
};

/// Runs on the wcom task.
static void _on_link_interruption(int link_id, enum wcom_interruption_reason reason)
{
    ESP_LOGI(TAG, "link %d closed (reason %d)", link_id, (int)reason);
    wcom_remove_link(link_id);
    _complete_reply(); /* A retired link can no longer deliver pending output. */
    // Tearing down TLS and the channel is the session task's job: it owns
    // those contexts again from here.
    xSemaphoreGive(_link_closed);
}

/// Runs on the wcom task.
static void _add_link_exec(struct wcom_operation *op)
{
    (void)op;

    int link_id = wcom_add_stream_link(&_stream_ops, NULL, _on_link_interruption);
    if (link_id < 0) {
        ESP_LOGE(TAG, "no free wcom link for the BLE session");
        xSemaphoreGive(_link_closed);
        return;
    }
    ESP_LOGI(TAG, "link %d up", link_id);
}

struct handshake_request {
    TaskHandle_t caller;
    esp_err_t result;
};
static void _handshake_work(void *arg)
{
    struct handshake_request *request=arg;
    request->result=wble_tls_session_start(_enrolled);
    ESP_LOGI(TAG,"BLE handshake worker stack free=%u",(unsigned)uxTaskGetStackHighWaterMark(NULL));
    xTaskNotifyGive(request->caller);
}
static void _handshake_task(void *arg)
{
    _handshake_work(arg);
    vTaskDelete(NULL);
}
static esp_err_t _run_session_handshake(void)
{
    struct handshake_request request={.caller=xTaskGetCurrentTaskHandle(),.result=ESP_FAIL};
#if CONFIG_WENDY_NET_PEER
    if(_enrolled && wendy_pki_work_available()){
        /* Physical BLE is a blocking baseline transport. Its native setup must
         * await retained admission outside the CPU queue; TLS math still uses
         * the existing work_run gate from this shared I/O worker. */
        if(!wendy_pki_io_work_submit(_handshake_work,&request))return ESP_ERR_NO_MEM;
        /* Only this coordinator submits BLE work, retaining its request until
         * notified. The live packet actor runs while TLS uses the existing
         * server stack instead of allocating another24KiB internal stack. */
        ulTaskNotifyTake(pdTRUE,portMAX_DELAY);
        return request.result;
    }
#endif
    /* Only the coordinator submits work and waits for completion before the
     * next session. The expensive certificate stack exists only while needed. */
    if (xTaskCreatePinnedToCore(_handshake_task,"ble-handshake",
            _enrolled ? PKI_SESSION_TASK_STACK : SESSION_TASK_STACK,&request,
            CONFIG_WENDY_BLE_TASK_PRIORITY,NULL,
            CONFIG_WENDY_BLE_TASK_CORE_AFFINITY)!=pdPASS) {
        ESP_LOGW(TAG,"insufficient memory for BLE handshake worker");
        return ESP_ERR_NO_MEM;
    }
    ulTaskNotifyTake(pdTRUE,portMAX_DELAY);
    return request.result;
}
static void _session_task(void *arg)
{
    (void)arg;
    static struct wcom_operation add_link_op = { .func = _add_link_exec };

    for (;;) {
        if (!wble_l2cap_wait_session(portMAX_DELAY))
            continue;

        ESP_LOGI(TAG, "session started");
        if (_run_session_handshake() == ESP_OK) {
            // Drop a stale signal from a previous session before handing the
            // stream over, or the wait below would return immediately.
            xSemaphoreTake(_link_closed, 0);
            wcom_core_exec(&add_link_op);
            xSemaphoreTake(_link_closed, portMAX_DELAY);
        }
        wble_tls_session_end();
        wble_l2cap_end_session();
        ESP_LOGI(TAG, "session ended");
    }
}


//--- public functions ---//

esp_err_t wendy_ble_host_init(void)
{
    wendy_ble_power_init();
    if (_host_initialized)
        return ESP_OK;

    esp_err_t err = nimble_port_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nimble_port_init failed: %s", esp_err_to_name(err));
        return err;
    }

    ble_hs_cfg.sync_cb  = _on_sync;
    ble_hs_cfg.reset_cb = _on_reset;

    ble_svc_gap_init();
    ble_svc_gatt_init();

    int rc = ble_gatts_count_cfg(_gatt_svcs);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gatts_count_cfg failed: %d", rc);
        return ESP_FAIL;
    }
    rc = ble_gatts_add_svcs(_gatt_svcs);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gatts_add_svcs failed: %d", rc);
        return ESP_FAIL;
    }

    // The host task must start last: services have to be registered before the
    // stack syncs and the GATT database is built.
    nimble_port_freertos_init(_host_task);

    _host_initialized = true;
    ESP_LOGI(TAG, "NimBLE host started");
    return ESP_OK;
}

esp_err_t wendy_ble_start(void)
{
    esp_err_t err = ESP_OK;

    if (wendy_pki_reset_in_progress()) {
        ESP_LOGW(TAG, "identity reset in progress; BLE disabled");
        return ESP_ERR_INVALID_STATE;
    }
    if (_started) {
        if (wendy_conf_has_enrollment() == _enrolled &&
            (!_enrolled || wendy_conf_is_current()))
            return ESP_OK;
        ESP_LOGW(TAG, "BLE identity changed since startup; reboot required");
        return ESP_ERR_INVALID_STATE;
    }
    _enrolled = wendy_conf_has_enrollment();
    if (_enrolled && !wendy_conf_is_current()) {
        ESP_LOGW(TAG, "BLE enrollment configuration unavailable; reboot required");
        return ESP_ERR_INVALID_STATE;
    }
#if !CONFIG_WENDY_PKI
    if (_enrolled) {
        ESP_LOGW(TAG, "PKI enrollment requires CONFIG_WENDY_PKI for BLE");
        return ESP_ERR_INVALID_STATE;
    }
#endif
#if CONFIG_WENDY_BLE_REQUIRE_MTLS
    if (!_enrolled) {
        ESP_LOGW(TAG, "BLE requires enrollment; use USB for setup");
        return ESP_ERR_INVALID_STATE;
    }
#endif

    // Snapshot the identity for the life of the advertisement. wendy_conf
    // fixes these at init and never changes them, so the copies are belt and
    // braces: they keep the advertisement owning the bytes it hands to NimBLE.
    _device_id    = strdup(wendy_conf_get_device_id());
    if (_enrolled) {
        char tenant[37], device[65];
        wendy_conf_enrollment_identity(tenant, device);
        if (device[0]) {
            free(_device_id);
            _device_id = strdup(device);
        }
    }
    _device_name  = strdup(wendy_conf_get_resolved_device_name());
    _display_name = strdup(wendy_conf_get_resolved_device_display_name());
    _principal[0] = 0;
    if (_enrolled) {
        char tenant[37], device[65];
        wendy_conf_get_enrolled_ids(tenant, device);
        if (device[0])
            snprintf(_principal, sizeof _principal, "spiffe://wendy.sh/tenant/%s/device/%s",
                     tenant, device);
    }
    if (!_device_id || !_device_name || !_display_name) {
        ESP_LOGE(TAG, "out of memory");
        err = ESP_ERR_NO_MEM;
        goto fail;
    }

    _build_mfg_data();

    _log_heap("before");
    err = wendy_ble_host_init();
    if (err != ESP_OK)
        goto fail;
    _log_heap("after");

    // Setting the GAP name takes NimBLE's host mutex, so the host must exist
    // first. Advertising remains gated on _started until setup is complete.
    // NimBLE copies the name, so failure cleanup may still free our string.
    ble_svc_gap_device_name_set(_device_name);

    err = wble_l2cap_init();
    if (err != ESP_OK)
        goto fail;

    _link_closed = xSemaphoreCreateBinary();
    if (!_link_closed) {
        ESP_LOGE(TAG, "semaphore allocation failed");
        err = ESP_ERR_NO_MEM;
        goto fail;
    }

    // A small coordinator remains idle; the certificate worker is allocated on demand.
    if (xTaskCreatePinnedToCore(_session_task, "wendy_ble",
                                SESSION_TASK_STACK, NULL,
                                CONFIG_WENDY_BLE_TASK_PRIORITY, NULL,
                                CONFIG_WENDY_BLE_TASK_CORE_AFFINITY) != pdPASS) {
        ESP_LOGE(TAG, "session task creation failed");
        err = ESP_ERR_NO_MEM;
        goto fail;
    }

    _started = true;

    if (_enrolled)
        ESP_LOGI(TAG, "PKI mTLS enabled: same-tenant operator certificate required");
    else
        ESP_LOGI(TAG, "unenrolled: clients may connect without a certificate");

    // If the host synced before this ran, _on_sync skipped advertising because
    // _started was still false; start it here instead.
    if (ble_hs_synced())
        _start_advertising(false);

    return ESP_OK;

fail:
    // _started is still false, so a caller may retry. Leave no half-built
    // state behind for that retry to leak or read.
    free(_device_id);
    free(_device_name);
    free(_display_name);
    _device_id = NULL;
    _device_name = NULL;
    _display_name = NULL;
    _principal[0] = 0;
    if (_link_closed) {
        vSemaphoreDelete(_link_closed);
        _link_closed = NULL;
    }
    return err;
}

#else /* !CONFIG_WENDY_BLE */

esp_err_t wendy_ble_host_init(void)
{
    ESP_LOGW(TAG, "CONFIG_WENDY_BLE is not set");
    return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t wendy_ble_start(void)
{
    return ESP_ERR_NOT_SUPPORTED;
}

#endif /* CONFIG_WENDY_BLE */
