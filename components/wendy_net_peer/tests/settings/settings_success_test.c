/* Ordinary saved policy, response transport fences and bounded application. */
#include <assert.h>
#include <stdio.h>
#include "../../src/settings.c"
static int64_t now;
static unsigned writes,changes;
static bool have_record,fail_write;
static struct record stored;
static const struct wcom_net_delegate *delegate;
int64_t esp_timer_get_time(void){return now;}
size_t heap_caps_get_total_size(unsigned caps){assert(caps==MALLOC_CAP_SPIRAM);
#ifdef TEST_PSRAM
 return 8*1024*1024;
#else
 return 0;
#endif
}
void wn_peer_runtime_status(WendyComNetStatus *s){s->state=WendyComNetState_WENDY_COM_NET_OFF;}
void wn_peer_configuration_changed(void){changes++;}
void wcom_cmd_set_net_delegate(const struct wcom_net_delegate *d){delegate=d;}
esp_err_t nvs_flash_init_partition(const char *name){assert(!strcmp(name,"wendy_pki"));return ESP_OK;}
esp_err_t nvs_open_from_partition(const char *partition,const char *space,int mode,nvs_handle_t *h)
{assert(!strcmp(partition,"wendy_pki")&&!strcmp(space,"net-settings"));*h=mode+1;return ESP_OK;}
void nvs_close(nvs_handle_t h){assert(h==1||h==2);}
esp_err_t nvs_get_blob(nvs_handle_t h,const char *key,void *out,size_t *size)
{assert(h==1&&!strcmp(key,"config")&&*size==sizeof stored);if(!have_record)return ESP_ERR_NVS_NOT_FOUND;memcpy(out,&stored,sizeof stored);return ESP_OK;}
esp_err_t nvs_set_blob(nvs_handle_t h,const char *key,const void *in,size_t size)
{assert(h==2&&!strcmp(key,"config")&&size==sizeof stored);if(fail_write)return ESP_FAIL;memcpy(&stored,in,size);have_record=true;writes++;return ESP_OK;}
esp_err_t nvs_commit(nvs_handle_t h){assert(h==2);return ESP_OK;}
static void applied(uint32_t token,bool drained)
{
 unsigned before=changes;
 now+=1000;delegate->reply_complete(token);wn_settings_poll(drained);assert(changes==before);
 now+=250000;wn_settings_poll(drained);
 if(drained)assert(changes==before+1);
}
int main(void)
{
 assert(wn_settings_init()==ESP_OK&&delegate&&!writes);
 WendyComNetStatus status;uint32_t token=999;
 assert(delegate->get(&status)==WendyComResult_WENDY_COM_RESULT_OK&&!status.desired.enabled);
 assert(status.ble_supported==!!CONFIG_WENDY_NET_BLE&&status.wifi_supported==!!CONFIG_WENDY_WIFI_ENABLED&&!status.nan_supported);
 WendyComNetConfig config=status.desired;
 config.enabled=true;
 if(!config.ble&&!config.infrastructure_wifi){config.ble=CONFIG_WENDY_NET_BLE;config.infrastructure_wifi=CONFIG_WENDY_WIFI_ENABLED;}
 assert(delegate->set(&config,&status,&token)==WendyComResult_WENDY_COM_RESULT_OK&&token&&writes==1);
 uint32_t first=token;assert(wn_settings_pending()&&!changes);
 now+=1000000;wn_settings_poll(true);assert(!changes);
 delegate->reply_complete(first+1);wn_settings_poll(true);assert(!changes);
 uint32_t ignored;
 assert(delegate->set(&config,&status,&ignored)==WendyComResult_WENDY_COM_RESULT_BUSY&&!ignored);
 applied(first,true);assert(changes==1&&!wn_settings_pending());
 assert(delegate->set(&config,&status,&token)==WendyComResult_WENDY_COM_RESULT_OK&&!token&&writes==1);
 config.enabled=false;
 assert(delegate->set(&config,&status,&token)==WendyComResult_WENDY_COM_RESULT_OK&&token&&writes==2);
 /* Old callbacks cannot complete a later settings generation. */
 delegate->reply_complete(first);wn_settings_poll(true);assert(changes==1);
 applied(token,false);assert(changes==1&&wn_settings_pending());
 now+=5000000;wn_settings_poll(false);assert(changes==2&&!wn_settings_pending());
 config.enabled=true;fail_write=true;
 assert(delegate->set(&config,&status,&token)==WendyComResult_WENDY_COM_RESULT_UNKNOWN_ERROR&&!token&&!status.desired.enabled&&!wn_settings_pending());fail_write=false;
 WendyComNetConfig unsupported=config;unsupported.nan=true;
 assert(delegate->set(&unsupported,&status,&token)==WendyComResult_WENDY_COM_RESULT_NET_NO_NAN&&!token);
#if !CONFIG_WENDY_NET_BLE
 unsupported=config;unsupported.ble=true;
 assert(delegate->set(&unsupported,&status,&token)==WendyComResult_WENDY_COM_RESULT_NET_NO_BLE);
#endif
#if !CONFIG_WENDY_WIFI_ENABLED
 unsupported=config;unsupported.infrastructure_wifi=true;
 assert(delegate->set(&unsupported,&status,&token)==WendyComResult_WENDY_COM_RESULT_NET_NO_WIFI);
#endif
#if WENDY_NET_NON_TRANSIT
 unsupported=config;unsupported.ble=unsupported.infrastructure_wifi=true;
 assert(delegate->set(&unsupported,&status,&token)==WendyComResult_WENDY_COM_RESULT_NET_ONE_CARRIER_ONLY);
 bool ble,wifi;assert(wendy_net_peer_boot_radios(&ble,&wifi)==ESP_OK&&!ble&&wifi);
 config.ble=true;config.infrastructure_wifi=false;
 assert(delegate->set(&config,&status,&token)==WendyComResult_WENDY_COM_RESULT_APPLIED_RESTARTING&&token&&status.restarting);
 assert(!wn_settings_restart_due());applied(token,true);assert(wn_settings_restart_due());
#else
 /* A client that vanishes before responding cannot stall settings forever. */
 assert(delegate->set(&config,&status,&token)==WendyComResult_WENDY_COM_RESULT_OK&&token);
 unsigned before=changes;now+=45000000;wn_settings_poll(false);assert(changes==before+1&&!wn_settings_pending());
#endif
 puts("native settings: bounded receipt, persistence, typed capabilities and runtime radio selection PASS");
}
