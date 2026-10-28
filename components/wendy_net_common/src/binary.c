#include "wendy_net_binary.h"
#include <limits.h>
#include <string.h>
void wn_raw(struct wn_writer *w,const void *data,size_t size)
{
    if(w->failed || w->size>w->maximum || size>w->maximum-w->size ||
       (w->data && (w->size>w->capacity || size>w->capacity-w->size)) || (!data && size)){
        w->failed=true;return;
    }
    if(w->data && size)memcpy(w->data+w->size,data,size);
    w->size+=size;
}
static void head(struct wn_writer *w,uint8_t major,uint64_t n)
{
    uint8_t bytes[9];size_t size=1;
    if(n<24)bytes[0]=(uint8_t)((major<<5)|n);
    else{
        unsigned k=n<=UINT8_MAX ? 1:n<=UINT16_MAX ? 2:n<=UINT32_MAX ? 4:8;
        bytes[0]=(uint8_t)((major<<5)|(k==1 ? 24:k==2 ? 25:k==4 ? 26:27));size+=k;
        for(unsigned i=0;i<k;i++)bytes[1+i]=(uint8_t)(n>>(8*(k-1-i)));
    }
    wn_raw(w,bytes,size);
}
void wn_map(struct wn_writer *w,size_t n){head(w,5,n);}
void wn_array(struct wn_writer *w,size_t n){head(w,4,n);}
void wn_text(struct wn_writer *w,const char *s)
{if(!s){w->failed=true;return;}size_t n=strlen(s);head(w,3,n);wn_raw(w,s,n);}
void wn_bytes(struct wn_writer *w,const void *data,size_t n){head(w,2,n);wn_raw(w,data,n);}
void wn_uint(struct wn_writer *w,uint64_t n){head(w,0,n);}
void wn_bool(struct wn_writer *w,bool b){uint8_t n=b ? 0xf5:0xf4;wn_raw(w,&n,1);}
int wn_finish(struct wn_writer *w)
{
    if(w->failed || !w->size || w->size>INT_MAX)return -1;
    if(w->data && w->size<w->capacity)w->data[w->size]=0;
    return (int)w->size;
}

/* Kept in sync with WendyOS netwire/keys.go. */
const char *wn_key_name(const char *name)
{
    if(!strcmp(name,"owner"))return "o";
    static const struct {const char *name,*key;} fields[]={
        {"Expires","e"},
        {"Issued","i"},
        {"added","a"},
        {"address","a"},
        {"agentPort","P"},
        {"agentTransport","T"},
        {"appEndpoints","a"},
        {"appId","a"},
        {"attachment","a"},
        {"ble","b"},
        {"body","b"},
        {"bundle","b"},
        {"caps","c"},
        {"catalog","C"},
        {"certificate","c"},
        {"certificates","c"},
        {"chain","c"},
        {"chunk","d"},
        {"credit","c"},
        {"data","d"},
        {"datagram","g"},
        {"device","d"},
        {"digest","h"},
        {"endpointListen","e"},
        {"error","e"},
        {"ethernet","E"},
        {"expires","e"},
        {"fingerprint","f"},
        {"fingerprints","f"},
        {"generation","G"},
        {"gossip","g"},
        {"hash","h"},
        {"hashes","h"},
        {"hello","h"},
        {"hops","h"},
        {"hostPort","h"},
        {"id","i"},
        {"incarnation","I"},
        {"index","i"},
        {"infrastructureWifi","i"},
        {"instance","n"},
        {"ipDatagram","i"},
        {"issued","i"},
        {"key","k"},
        {"kind","k"},
        {"link_id","l"},
        {"listen","l"},
        {"live","l"},
        {"manifest","m"},
        {"mesh","m"},
        {"missing","m"},
        {"mtu","m"},
        {"name","n"},
        {"nan","n"},
        {"nonce","n"},
        {"offset","f"},
        {"op","o"},
        {"operator","o"},
        {"operatorCertificate","O"},
        {"operatorReceipts","o"},
        {"origin","o"},
        {"peer","p"},
        {"peers","p"},
        {"platform","l"},
        {"port","p"},
        {"prefix","p"},
        {"previous","p"},
        {"principal","p"},
        {"proof","p"},
        {"receipts","c"},
        {"record","R"},
        {"request","r"},
        {"requester","r"},
        {"requires","q"},
        {"retainUntil","r"},
        {"revision","R"},
        {"role","r"},
        {"route","r"},
        {"router","r"},
        {"routerID","r"},
        {"routerId","r"},
        {"rx","r"},
        {"self","s"},
        {"seqno","s"},
        {"serviceId","s"},
        {"services","s"},
        {"signature","s"},
        {"stream","s"},
        {"time","t"},
        {"total","l"},
        {"transcript","t"},
        {"transport","t"},
        {"tx","T"},
        {"txt","x"},
        {"type","t"},
        {"until","u"},
        {"used","u"},
        {"v","v"},
        {"version","v"},
        {"withdraw","w"},
    };
    if(!name || !name[0] || !name[1])return name;
    size_t lo=0,hi=sizeof fields/sizeof fields[0];
    while(lo<hi){size_t mid=lo+(hi-lo)/2;int c=strcmp(name,fields[mid].name);
        if(!c)return fields[mid].key;
        if(c<0)hi=mid;else lo=mid+1;
    }
    return name;
}
void wn_key(struct wn_writer *w,const char *name){wn_text(w,wn_key_name(name));}
