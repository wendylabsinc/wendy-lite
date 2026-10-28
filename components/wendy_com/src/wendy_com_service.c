#include "wendy_com_service.h"
#include "wendy_com_cmd.h"
#include "wendy_conf.h"
#include <stdio.h>
#include <string.h>

#ifndef CONFIG_WENDY_SERVER_PORT
#define CONFIG_WENDY_SERVER_PORT 5054
#endif
int wcom_service_snapshot(struct wcom_service *service)
{
    memset(service,0,sizeof *service);
    service->instance=wendy_conf_get_resolved_device_display_name();
    service->port=CONFIG_WENDY_SERVER_PORT;
    wendy_conf_get_enrolled_ids(service->tenant,service->device);
    bool enrolled=wendy_conf_has_enrollment();
    if(enrolled && (strlen(service->tenant)!=36 || strlen(service->device)!=36))return -1;
    const char *device=enrolled ? service->device:wendy_conf_get_device_id();
    service->txt[service->count++]=(struct wcom_service_txt){"id",device};
    service->txt[service->count++]=(struct wcom_service_txt){"name",wendy_conf_get_resolved_device_name()};
    service->txt[service->count++]=(struct wcom_service_txt){"displayname",service->instance};
    service->txt[service->count++]=(struct wcom_service_txt){"mtls",enrolled ? "true":"false"};
    service->txt[service->count++]=(struct wcom_service_txt){"platform","Lite"};
    if(enrolled){
        snprintf(service->principal,sizeof service->principal,"spiffe://wendy.sh/tenant/%.36s/device/%.36s",service->tenant,service->device);
        service->txt[service->count++]=(struct wcom_service_txt){"tenant",service->tenant};
        service->txt[service->count++]=(struct wcom_service_txt){"principal",service->principal};
    }
    if(wcom_cmd_sensor_link_available())service->txt[service->count++]=(struct wcom_service_txt){"caps","sensors"};
    return 0;
}
int wcom_service_txt(const struct wcom_service *service,const char **out,char *bytes,size_t capacity)
{
    size_t used=0;
    for(size_t i=0;i<service->count;i++){
        size_t key=strlen(service->txt[i].key),value=strlen(service->txt[i].value);
        if(key+value+1>255 || used>capacity || key+value+2>capacity-used)return -1;
        out[i]=bytes+used;
        memcpy(bytes+used,service->txt[i].key,key);bytes[used+key]='=';
        memcpy(bytes+used+key+1,service->txt[i].value,value+1);used+=key+value+2;
    }
    return (int)used;
}
