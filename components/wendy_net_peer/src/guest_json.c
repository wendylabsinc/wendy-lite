/* JSON is retained only at the local WASM service ABI, never on the mesh. */
#include "wendy_net_service_protocol.h"
#include "wendy_net_peer_protocol.h"
#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
struct output {char *bytes;size_t capacity,size;bool failed;size_t maximum;};
static void raw(struct output *w,const char *bytes,size_t n)
{
    if(w->size>w->maximum || n>w->maximum-w->size){w->failed=true;return;}
    if(w->bytes){
        if(w->size>=w->capacity || n>=w->capacity-w->size){w->failed=true;return;}
        memcpy(w->bytes+w->size,bytes,n);
    }
    w->size+=n;
}
static void literal(struct output *w,const char *s){raw(w,s,strlen(s));}
static void number(struct output *w,uint64_t value)
{char s[21];int n=snprintf(s,sizeof s,"%" PRIu64,value);raw(w,s,(size_t)n);}
/* Match encoding/json's escaping, including HTML and JavaScript line breaks.
 * This keeps the signature valid when a Go peer forwards a RawMessage body. */
static void string(struct output *w,const char *s)
{
    static const char hex[]="0123456789abcdef";
    literal(w,"\"");
    if(!s){w->failed=true;return;}
    for(const unsigned char *p=(const unsigned char*)s;*p;p++){
        unsigned c=*p;
        if(c=='"' || c=='\\'){char escaped[2]={'\\',(char)c};raw(w,escaped,2);}
        else if(c=='\b')literal(w,"\\b");else if(c=='\f')literal(w,"\\f");
        else if(c=='\n')literal(w,"\\n");else if(c=='\r')literal(w,"\\r");
        else if(c=='\t')literal(w,"\\t");
        else if(c<32 || c=='<' || c=='>' || c=='&'){
            char escaped[6]={'\\','u','0','0',hex[c>>4],hex[c&15]};raw(w,escaped,6);
        }else if(c==0xe2 && p[1]==0x80 && (p[2]==0xa8 || p[2]==0xa9)){
            literal(w,p[2]==0xa8 ? "\\u2028":"\\u2029");p+=2;
        }else raw(w,(const char*)p,1);
    }
    literal(w,"\"");
}
static int finish(struct output *w,size_t maximum)
{
    if(w->failed || !w->size || w->size>maximum)return -1;
    if(w->bytes)w->bytes[w->size]=0;
    return (int)w->size;
}
int wns_record_json(const struct wns_record *r,char *out,size_t cap)
{
    if(!r || r->txt_count>WNS_TXT_MAX ||
        r->issued<=0 || r->expires<=r->issued)return -1;
    struct output w={out,cap,0,false,WNS_WIRE_MAX};
    literal(&w,"{\"version\":1,\"key\":{\"mesh\":");string(&w,r->mesh);
    literal(&w,",\"device\":");string(&w,r->principal);
    literal(&w,",\"appId\":");string(&w,r->app);
    literal(&w,",\"serviceId\":");string(&w,r->service);
    literal(&w,"},\"generation\":");number(&w,r->generation);
    literal(&w,",\"type\":");string(&w,r->type);
    literal(&w,",\"instance\":");string(&w,r->instance);
    literal(&w,",\"hostPort\":");number(&w,r->port);
    if(r->txt_count){
        literal(&w,",\"txt\":[");
        for(unsigned i=0;i<r->txt_count;i++){
            char value[256];if(wns_record_txt(r,i,value,sizeof value)<0){w.failed=true;break;}
            if(i)literal(&w,",");
            string(&w,value);
        }
        literal(&w,"]");
    }
    literal(&w,",\"issued\":");number(&w,(uint64_t)r->issued);
    literal(&w,",\"expires\":");number(&w,(uint64_t)r->expires);
    if(r->withdraw)literal(&w,",\"withdraw\":true");
    literal(&w,"}");return finish(&w,WNS_BODY_MAX);
}

int wns_spec_from_json(const void *data,size_t size,char **out,size_t *bytes)
{
    if(!out || !bytes)return -1;
    *out=NULL;*bytes=0;
    if(!data || !size || size>WNS_BODY_MAX)return -1;
    const char *end=NULL;cJSON *root=cJSON_ParseWithLengthOpts(data,size,&end,0);
    if(!root)return -1;
    int result=-1;
    while(end<(const char*)data+size && strchr(" \t\r\n",*end))end++;
    if(end!=(const char*)data+size || !cJSON_IsObject(root))goto done;
    unsigned fields=0;
    for(cJSON *item=root->child;item;item=item->next){
        if(!item->string || (strcmp(item->string,"serviceId") && strcmp(item->string,"type") &&
           strcmp(item->string,"instance") && strcmp(item->string,"port") && strcmp(item->string,"txt")))goto done;
        for(cJSON *old=root->child;old!=item;old=old->next)if(!strcmp(old->string,item->string))goto done;
        if(++fields>5)goto done;
    }
    cJSON *service=cJSON_GetObjectItemCaseSensitive(root,"serviceId"),*type=cJSON_GetObjectItemCaseSensitive(root,"type"),
        *instance=cJSON_GetObjectItemCaseSensitive(root,"instance"),*port=cJSON_GetObjectItemCaseSensitive(root,"port"),
        *txt=cJSON_GetObjectItemCaseSensitive(root,"txt");
    if(!cJSON_IsString(service) || !cJSON_IsString(type) || !cJSON_IsString(instance) || !cJSON_IsNumber(port) ||
       port->valuedouble<1 || port->valuedouble>65535 || port->valuedouble!=(unsigned)port->valuedouble ||
       (txt && !cJSON_IsArray(txt)))goto done;
    int count=txt ? cJSON_GetArraySize(txt):0;if(count<0 || count>WNS_TXT_MAX)goto done;
    for(int i=0;i<count;i++)if(!cJSON_IsString(cJSON_GetArrayItem(txt,i)))goto done;
    size_t cap=size+64;if(cap>WNS_BODY_MAX)cap=WNS_BODY_MAX;
    /* Public output ownership is libc; callers outside this component may free it. */
    char *binary=malloc(cap);if(!binary){result=-2;goto done;}
    struct wn_writer w={.data=(uint8_t*)binary,.capacity=cap,.maximum=WNS_BODY_MAX};
    wn_map(&w,4+(txt ? 1:0));
    if(txt){wn_key(&w,"txt");wn_array(&w,(size_t)count);for(int i=0;i<count;i++)wn_text(&w,cJSON_GetArrayItem(txt,i)->valuestring);}
    wn_key(&w,"port");wn_uint(&w,(uint64_t)port->valuedouble);wn_key(&w,"type");wn_text(&w,type->valuestring);
    wn_key(&w,"instance");wn_text(&w,instance->valuestring);wn_key(&w,"serviceId");wn_text(&w,service->valuestring);
    int n=wn_finish(&w);if(n<0){free(binary);goto done;}
    *out=binary;*bytes=(size_t)n;result=0;
done:
    cJSON_Delete(root);return result;
}
