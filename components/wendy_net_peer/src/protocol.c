/* UUID and bounded native CBOR protocol helpers. */
#include "wendy_net_peer_protocol.h"
#include <inttypes.h>
#ifdef ESP_PLATFORM
#include "lwip/sockets.h"
#else
#include <arpa/inet.h>
#endif
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

uint16_t wn_get16(const uint8_t* p)
{
    return (uint16_t)((unsigned)p[0] << 8 | p[1]);
}
uint32_t wn_get32(const uint8_t* p)
{
    return (uint32_t)wn_get16(p) << 16 | wn_get16(p + 2);
}
void wn_put16(uint8_t* p, uint16_t v)
{
    p[0] = v >> 8;
    p[1] = v;
}
void wn_put32(uint8_t* p, uint32_t v)
{
    wn_put16(p, v >> 16);
    wn_put16(p + 2, v);
}
static int hex(char c)
{
    return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
}
int wn_uuid_parse(const char* s, uint8_t out[16])
{
    if (!s || strlen(s) != 36)
        return -1;
    unsigned n = 0;
    for (unsigned i = 0; i < 36;)
    {
        if (i == 8 || i == 13 || i == 18 || i == 23)
        {
            if (s[i++] != '-')
                return -1;
            continue;
        }
        int a = hex(s[i++]), b = hex(s[i++]);
        if (a < 0 || b < 0)
            return -1;
        out[n++] = (uint8_t)(a * 16 + b);
    }
    return 0; /* Any canonical UUID, matching the shared meshid contract. */
}
void wn_uuid_format(const uint8_t u[16], char out[37])
{
    snprintf(out, 37, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", u[0],
        u[1], u[2], u[3], u[4], u[5], u[6], u[7], u[8], u[9], u[10], u[11], u[12], u[13], u[14],
        u[15]);
}
void wn_address(const uint8_t u[16], uint8_t out[16])
{
    static const uint8_t prefix[] = { 0xfd, 0x45, 0xb8, 0x91, 0x56, 0x7f };
    memcpy(out, prefix, 6);
    memcpy(out + 6, u + 6, 10);
}
int wn_device_hostname_parse(const char *host,uint8_t device[16])
{
    static const char *const suffixes[]={".mesh.wendy.internal",".mesh.local"};
    if(!host || !device)return 0;
    size_t size=strlen(host);
    if(size && host[size-1]=='.')size--;
    for(unsigned i=0;i<sizeof suffixes/sizeof suffixes[0];i++){
        size_t suffix_size=strlen(suffixes[i]);
        if(size!=7+36+suffix_size || strncasecmp(host,"device-",7) ||
           strncasecmp(host+7+36,suffixes[i],suffix_size))continue;
        char uuid[37];
        for(unsigned j=0;j<36;j++){
            char c=host[7+j];uuid[j]=c>='A' && c<='F' ? c+'a'-'A':c;
        }
        uuid[36]=0;
        return wn_uuid_parse(uuid,device) ? -1:1;
    }
    return 0;
}
void wn_prefix(const uint8_t u[16], char out[48])
{
    uint8_t a[16];
    wn_address(u, a);
    snprintf(out, 48, "fd45:b891:567f:%x:%x:%x:%x:%x/128", wn_get16(a + 6), wn_get16(a + 8),
        wn_get16(a + 10), wn_get16(a + 12), wn_get16(a + 14));
}
int wn_principal(const char* tenant, const char* device, char out[106])
{
    uint8_t u[16];
    if (wn_uuid_parse(tenant, u) || wn_uuid_parse(device, u))
        return -1;
    int n = snprintf(out, 106, "spiffe://wendy.sh/tenant/%s/device/%s", tenant, device);
    return n == 105 ? n : -1;
}
int wn_principal_device(const char* s, const char* tenant, uint8_t device[16])
{
    char expected[106];
    if (!s || strlen(s) != 105 || wn_uuid_parse(s + 69, device)
        || wn_principal(tenant, s + 69, expected) < 0)
        return -1;
    return strcmp(s, expected) ? -1 : 0;
}

int wn_manifest_write(const uint8_t self[16], const struct wn_origin *origin,
    uint64_t revision, int64_t issued, int64_t expires, uint16_t port, char *out, size_t cap)
{
    return wn_manifest_app_write(self,origin,revision,issued,expires,port,0,out,cap);
}
int wn_manifest_app_write(const uint8_t self[16],const struct wn_origin *origin,
    uint64_t revision,int64_t issued,int64_t expires,uint16_t port,uint16_t app_port,
    char *out,size_t cap)
{
    return wn_manifest_capabilities_write(self,origin,revision,issued,expires,port,
        app_port,NULL,false,out,cap);
}
int wn_manifest_capabilities_write(const uint8_t self[16],const struct wn_origin *origin,
    uint64_t revision,int64_t issued,int64_t expires,uint16_t port,uint16_t app_port,
    const char *display_name,bool sensors,char *out,size_t cap)
{
    return wn_manifest_services_write(self,origin,revision,issued,expires,port,app_port,
        display_name,sensors,NULL,0,out,cap);
}
int wn_manifest_services_write(const uint8_t self[16],const struct wn_origin *origin,
    uint64_t revision,int64_t issued,int64_t expires,uint16_t port,uint16_t app_port,
    const char *display_name,bool sensors,const void *services,size_t services_size,char *out,size_t cap)
{
    if (!self || !origin || !revision || !origin->router_id || origin->router_id == UINT64_MAX ||
        issued <= 0 || expires <= issued || expires-issued > 900000 || !port) return -1;
    char device[37], prefix[48];
    wn_uuid_format(self, device);
    wn_prefix(self, prefix);
    char name[16];snprintf(name,sizeof name,"esp32-%.8s",device);
    if(display_name && strlen(display_name)>255)return -1;
    struct wn_writer w={.data=(uint8_t*)out,.capacity=cap,.maximum=WN_MANIFEST_BODY_MAX};
    wn_map(&w,13);
    wn_key(&w,"agentPort");wn_uint(&w,port);
    wn_key(&w,"revision");wn_uint(&w,revision);
    wn_key(&w,"agentTransport");wn_text(&w,"mtls-v1");
    wn_key(&w,"appEndpoints");wn_array(&w,app_port ? 1:0);
    if(app_port){wn_map(&w,2);wn_key(&w,"port");wn_uint(&w,app_port);wn_key(&w,"transport");wn_text(&w,"tls-v1");}
    wn_key(&w,"caps");wn_array(&w,sensors ? 1:0);if(sensors)wn_text(&w,"sensors");
    wn_key(&w,"device");wn_text(&w,device);
    wn_key(&w,"Expires");wn_uint(&w,(uint64_t)expires);
    wn_key(&w,"Issued");wn_uint(&w,(uint64_t)issued);
    wn_key(&w,"platform");wn_text(&w,"Lite");
    wn_key(&w,"name");wn_text(&w,display_name && *display_name ? display_name:name);
    wn_key(&w,"route");wn_map(&w,3);
    wn_key(&w,"prefix");wn_text(&w,prefix);wn_key(&w,"routerId");wn_uint(&w,origin->router_id);
    wn_key(&w,"seqno");wn_uint(&w,origin->seqno);
    wn_key(&w,"services");if(services)wn_raw(&w,services,services_size);else wn_array(&w,0);
    wn_key(&w,"version");wn_uint(&w,4);return wn_finish(&w);
}
int wn_manifest_wire_write(const char *principal,const void *body,size_t size,
    const uint8_t *signature,size_t signature_size,char *out,size_t cap)
{
    if(!principal || strlen(principal)!=105 || !body || !size || size>WN_MANIFEST_BODY_MAX ||
       !signature || signature_size<8 || signature_size>WN_ORIGIN_SIGNATURE_MAX)return -1;
    struct wn_writer w={.data=(uint8_t*)out,.capacity=cap,.maximum=WN_MANIFEST_WIRE_MAX};
    wn_map(&w,3);wn_key(&w,"body");wn_raw(&w,body,size);
    wn_key(&w,"principal");wn_text(&w,principal);wn_key(&w,"signature");wn_bytes(&w,signature,signature_size);
    return wn_finish(&w);
}
int wn_identity_request_write(const char *principal,char *out,size_t cap)
{
    if(!principal || !out)return -1;
    struct wn_writer w={.data=(uint8_t*)out,.capacity=cap,.maximum=WN_CONTROL_MAX};
    wn_map(&w,2);wn_key(&w,"kind");wn_text(&w,"identity-request");
    wn_key(&w,"principal");wn_text(&w,principal);return wn_finish(&w);
}
int wn_manifest_request_write(const char *principal,char *out,size_t cap)
{
    if(!principal || !out)return -1;
    struct wn_writer w={.data=(uint8_t*)out,.capacity=cap,.maximum=WN_CONTROL_MAX};
    wn_map(&w,2);wn_key(&w,"kind");wn_text(&w,"manifest-request");
    wn_key(&w,"principal");wn_text(&w,principal);return wn_finish(&w);
}

int wn_directory_missing_write(const char *principal,bool manifest,char *out,size_t cap)
{
    if(!principal || !out)return -1;
    struct wn_writer w={.data=(uint8_t*)out,.capacity=cap,.maximum=WN_CONTROL_MAX};
    wn_map(&w,2);wn_key(&w,"kind");wn_text(&w,manifest ? "manifest-missing":"identity-missing");
    wn_key(&w,"principal");wn_text(&w,principal);return wn_finish(&w);
}

bool wn_ip_admits(const uint8_t self[16], const void *data, size_t size, bool incoming)
{
    static const uint8_t prefix[6] = {0xfd,0x45,0xb8,0x91,0x56,0x7f};
    const uint8_t *p = data;
    if (!self || !p || size < 40 || size > WN_MTU || p[0]>>4 != 6 || wn_get16(p+4) != size-40 ||
        memcmp(p+8,prefix,6) || memcmp(p+24,prefix,6)) return false;
    uint8_t address[16];
    wn_address(self,address);
    return !memcmp(p+(incoming?24:8),address,16);
}
