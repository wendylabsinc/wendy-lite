/* Matching native service metadata, local guest JSON and inherited leases. */
#include "wendy_net_service_protocol.h"
#include "wendy_net_alloc.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int service(struct wn_writer *w,unsigned id)
{
    char name[32];snprintf(name,sizeof name,"room.%u",id);
    wn_map(w,7);wn_key(w,"a");wn_text(w,"app.test");wn_key(w,"m");wn_text(w,"default.lan");
    wn_key(w,"s");wn_text(w,name);wn_key(w,"n");wn_text(w,"Room");wn_key(w,"t");wn_text(w,"_sensor._tcp");
    wn_key(w,"p");wn_uint(w,7000+id);wn_key(w,"x");wn_array(w,1);wn_text(w,"unit=celsius");return 0;
}
static int services(unsigned count,bool repeat,char *out,size_t cap)
{
    struct wn_writer w={.data=(uint8_t*)out,.capacity=cap,.maximum=WN_MANIFEST_BODY_MAX};
    wn_map(&w,1);wn_key(&w,"services");wn_array(&w,count);
    for(unsigned i=0;i<count;i++)service(&w,repeat ? 0:i);
    return wn_finish(&w);
}
int main(void)
{
#if defined(WENDY_NET_MEMORY_HOST_BUDGET_TEST)
    assert(wendy_net_runtime_memory_open());
#endif
    const char json[]="{\"serviceId\":\"room.temperature\",\"type\":\"_sensor._tcp\",\"instance\":\"Room\",\"port\":7000,\"txt\":[\"unit=celsius\"]}";
    char *binary=NULL;size_t bytes=0;assert(!wns_spec_from_json(json,sizeof json-1,&binary,&bytes));
    struct wns_record record;assert(!wns_spec_read(binary,bytes,&record));
    assert(!strcmp(record.service,"room.temperature") && record.port==7000);
    char txt[256];assert(wns_record_txt(&record,0,txt,sizeof txt)==12 && !strcmp(txt,"unit=celsius"));
    free(binary);
    assert(wns_label_valid("room.temperature") && wns_label_valid("room_1"));
    assert(wns_type_valid("_-sensor._udp") && wns_type_valid("_sensor._tcp"));
    assert(!wns_label_valid("Room") && !wns_type_valid("_Sensor._tcp"));
    assert(wns_app_id_valid("APP_1.example") && !wns_app_id_valid(".."));
    char wire[WN_MANIFEST_BODY_MAX];struct wn_doc doc;
    for(unsigned count=0;count<=256;count=count ? count*2:1){
        int n=services(count,false,wire,sizeof wire);assert(n>0);
        assert(!wn_doc_parse_array_view(&doc,wire,(size_t)n,sizeof wire,"services"));
        assert(!wns_manifest_services_validate(&doc,0));
        if(count==256)break;
    }
    int n=services(2,true,wire,sizeof wire);assert(n>0);
    assert(!wn_doc_parse_array_view(&doc,wire,(size_t)n,sizeof wire,"services"));
    assert(wns_manifest_services_validate(&doc,0)<0);
#if defined(WENDY_NET_MEMORY_HOST_BUDGET_TEST)
    wendy_net_runtime_memory_close();assert(wendy_net_runtime_memory_drained());
#endif
    puts("Shared service schema: local text API, compact CBOR, 256 entries and exact identity uniqueness");
}
