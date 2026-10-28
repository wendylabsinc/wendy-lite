#include "wendy_com_service.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static bool sensors;
const char *wendy_conf_get_device_id(void){return "aabbccddeeff";}
const char *wendy_conf_get_resolved_device_name(void){return "wendy-lab";}
const char *wendy_conf_get_resolved_device_display_name(void){return "Lab sensor";}
bool wendy_conf_has_enrollment(void){return true;}
void wendy_conf_get_enrolled_ids(char tenant[37],char device[65])
{strcpy(tenant,"11111111-1111-4111-8111-111111111111");strcpy(device,"22222222-2222-4222-8222-222222222222");}
bool wcom_cmd_sensor_link_available(void){return sensors;}
static void check(bool provider)
{
    sensors=provider;struct wcom_service s;
    assert(!wcom_service_snapshot(&s));
    assert(s.port==5054 && !strcmp(s.instance,"Lab sensor"));
    const char *txt[WCOM_SERVICE_TXT_MAX];char bytes[1200];
    assert(wcom_service_txt(&s,txt,bytes,sizeof bytes)>0);
    bool caps=false,id=false,principal=false,mtls=false;
    for(size_t i=0;i<s.count;i++){
        /* Mesh receives exactly the key/value strings supplied to LAN mDNS. */
        size_t key=strlen(s.txt[i].key);
        assert(!strncmp(txt[i],s.txt[i].key,key) && txt[i][key]=='=' && !strcmp(txt[i]+key+1,s.txt[i].value));
        if(!strcmp(txt[i],"caps=sensors"))caps=true;
        if(!strcmp(txt[i],"id=22222222-2222-4222-8222-222222222222"))id=true;
        if(!strcmp(txt[i],"mtls=true"))mtls=true;
        if(!strcmp(s.txt[i].key,"principal"))principal=!strcmp(s.txt[i].value,
            "spiffe://wendy.sh/tenant/11111111-1111-4111-8111-111111111111/device/22222222-2222-4222-8222-222222222222");
    }
    assert(caps==provider && id && principal && mtls);
}
int main(void)
{check(false);check(true);check(false);puts("LAN and mesh share the enrolled WendyCom service and actual sensor capability");}
