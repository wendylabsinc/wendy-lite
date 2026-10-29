#include "wendy_pki_mesh.h"
#include "wendy_pki_public_index.h"
#include "wendy_pki_der_cache.h"
#include "wendy_conf.h"
#include <string.h>

static bool current(const struct wendy_pki_mesh_identity *clock,uint32_t epoch)
{
    return !wendy_pki_reset_in_progress() &&
        epoch==pki_public_certificate_epoch() &&
        wendy_conf_snapshot_current(clock->config_generation);
}
int wendy_pki_mesh_local_part_snapshot(const struct wendy_pki_mesh_identity *clock,
    uint32_t epoch,const uint8_t hash[32],size_t offset,uint8_t out[1024],size_t *total)
{
    if(!clock || !hash || !out || !total)return -1;
    *total=0;
    if(!current(clock,epoch))return -1;
    char tenant[37],device[65];wendy_conf_enrollment_identity(tenant,device);
    if(strcmp(tenant,clock->tenant) || strcmp(device,clock->device))return -1;
    /* TLS setup already initialized this identity partition before publishing
     * its verified public index. This worker-only reader never initializes,
     * prepares, repairs, writes, or locks the private identity state. */
    nvs_handle_t handle;
    if(nvs_open_from_partition("wendy_pki","identity",NVS_READONLY,&handle)!=ESP_OK)return -1;
    int result=-1;int64_t pending=0;
    esp_err_t marker=nvs_get_i64(handle,"reset_pending",&pending);
    if((marker==ESP_ERR_NVS_NOT_FOUND || (marker==ESP_OK && !pending)) && current(clock,epoch)){
        struct pki_der_source source;
        if(!pki_der_cache_open(handle,&source))
            result=pki_der_cache_part(&source,hash,offset,out,total);
    }
    nvs_close(handle);
    /* Certificate/cache writers retire the epoch BEFORE their first public
     * mutation. Every returned slice was also checked against the full DER
     * content hash; a concurrent renewal/reset cannot publish mixed bytes. */
    if(!current(clock,epoch))result=-1;
    if(result<0)*total=0;
    return result;
}
