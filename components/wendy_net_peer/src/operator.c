/* SPDX-License-Identifier: Apache-2.0 */
#include "wendy_net_operator.h"
#include "wendy_net_alloc.h"
#include "wendy_pki_crypto.h"
#include <psa/crypto.h>
#ifdef ESP_PLATFORM
#include "lwip/sockets.h"
#else
#include <arpa/inet.h>
#endif
#include <limits.h>
#include <string.h>

bool wno_in_pool(const uint8_t address[16])
{static const uint8_t prefix[]={0xfd,0x45,0xb8,0x91,0x56,0x80};return address && !memcmp(address,prefix,sizeof prefix);}
int wno_address(const char *principal,size_t size,const uint8_t instance[16],uint8_t out[16])
{
    static const uint8_t domain[]="wendy-net/operator-address/v1";
    if(!instance || !out || wendy_pki_operator_principal(principal,size,NULL) || wendy_pki_crypto_init())return -1;
    uint8_t length[4];wn_put32(length,(uint32_t)size);uint8_t digest[32];size_t written=0;
    psa_hash_operation_t operation=PSA_HASH_OPERATION_INIT;
    bool okay=psa_hash_setup(&operation,PSA_ALG_SHA_256)==PSA_SUCCESS &&
        psa_hash_update(&operation,domain,sizeof domain)==PSA_SUCCESS &&
        psa_hash_update(&operation,length,sizeof length)==PSA_SUCCESS &&
        psa_hash_update(&operation,(const uint8_t*)principal,size)==PSA_SUCCESS &&
        psa_hash_update(&operation,instance,16)==PSA_SUCCESS &&
        psa_hash_finish(&operation,digest,sizeof digest,&written)==PSA_SUCCESS && written==sizeof digest;
    psa_hash_abort(&operation);if(!okay)return -1;
    memcpy(out,(const uint8_t[]){0xfd,0x45,0xb8,0x91,0x56,0x80},6);memcpy(out+6,digest,10);return 0;
}
static int number(const struct wn_doc *d,unsigned at,const char *name,uint64_t *out)
{return wn_doc_u64(d,wn_doc_member(d,at,name),out);}
static bool normalized(const char *s,size_t n)
{
    if(!n || n>64)return false;
    for(size_t i=0;i<n;i++){unsigned char c=s[i];if(!((c>='a' && c<='z') || (c>='0' && c<='9') || (i && (c=='.' || c=='_' || c=='/' || c=='-'))))return false;}
    return true;
}
int wno_manifest_read(const void *wire,size_t size,const char *tenant,struct wno_manifest *out)
{
    if(!out)return -1;
    struct wn_doc d;if(wn_doc_parse_array_view(&d,wire,size,WNO_ARTIFACT_MAX,"s"))return -1;
    /* Required members are checked below; future optional envelope members
     * do not change the exact signed principal/body preimage. */
    struct wno_manifest p={.envelope=wire,.envelope_size=size};
    if(wn_doc_text(&d,wn_doc_member(&d,0,"principal"),&p.principal,&p.principal_size) ||
       wendy_pki_operator_principal(p.principal,p.principal_size,tenant) ||
       wn_doc_bytes(&d,wn_doc_member(&d,0,"signature"),&p.signature,&p.signature_size) ||
       !p.signature_size || p.signature_size>8192)return -1;
    /* Match ordinary device origins: a larger supported-by-WendyOS scheme is
     * outside this verifier's current bound, not a reason to drop a carrier. */
    if(p.signature_size>WENDY_PKI_MESH_SIGNATURE_MAX)return WNO_UNSUPPORTED;
    int body=wn_doc_member(&d,0,"body");
    if(body<0 || d.tokens[body].type!='{')return -1;
    p.body=(const uint8_t*)d.text+d.tokens[body].start;p.body_size=d.tokens[body].end-d.tokens[body].start;
    if(p.body_size>WENDY_PKI_OPERATOR_BODY_MAX)return -1;
    uint64_t version,issued,expires,port;
    if(number(&d,(unsigned)body,"version",&version))return -1;
    if(version!=4)return WNO_UNSUPPORTED;
    int owner=wn_doc_member(&d,(unsigned)body,"owner");
    const char *principal;size_t principal_size;char instance[37],device[37];uint8_t zero[16]={0},device_id[16];
    if(owner<0 || d.tokens[owner].type!='{' ||
       wn_doc_text(&d,wn_doc_member(&d,(unsigned)owner,"principal"),&principal,&principal_size) ||
       principal_size!=p.principal_size || memcmp(principal,p.principal,p.principal_size) ||
       wn_doc_string(&d,wn_doc_member(&d,(unsigned)owner,"instance"),instance,sizeof instance)<0 ||
       wn_uuid_parse(instance,p.instance) || !memcmp(p.instance,zero,16) ||
       wn_doc_string(&d,wn_doc_member(&d,(unsigned)body,"device"),device,sizeof device)<0 ||
       wn_uuid_parse(device,device_id) || memcmp(device_id,zero,16) ||
       number(&d,(unsigned)body,"agentPort",&port) || port ||
       number(&d,(unsigned)body,"revision",&p.revision) || !p.revision ||
       number(&d,(unsigned)body,"Issued",&issued) || issued>INT64_MAX ||
       number(&d,(unsigned)body,"Expires",&expires) || expires>INT64_MAX || expires<=issued || expires-issued>900000)return -1;
    int hashes=wn_doc_member(&d,(unsigned)owner,"hashes");
    if(hashes<0 || d.tokens[hashes].type!='[')return -1;
    for(unsigned i=(unsigned)hashes+1;i<d.tokens[hashes].next;i=d.tokens[i].next){
        size_t n;if(p.hash_count==16 || wn_doc_bytes(&d,(int)i,&p.hashes[p.hash_count],&n) || n!=32)return -1;
        p.hash_count++;
    }
    if(!p.hash_count)return -1;
    p.issued=(int64_t)issued;p.expires=(int64_t)expires;
    int withdraw=wn_doc_member(&d,(unsigned)body,"withdraw");
    if(withdraw>=0){if(d.tokens[withdraw].type!='t' && d.tokens[withdraw].type!='f')return -1;p.withdraw=d.tokens[withdraw].type=='t';}
    int required=wn_doc_member(&d,(unsigned)body,"requires");
    if(required>=0){
        if(d.tokens[required].type!='[')return -1;
        unsigned count=0;
        for(unsigned i=(unsigned)required+1;i<d.tokens[required].next;i=d.tokens[i].next){
            const char *name;size_t n;if(++count>16 || wn_doc_text(&d,(int)i,&name,&n) || !normalized(name,n))return -1;
        }
        if(count)return WNO_UNSUPPORTED;
    }
    static const char *const arrays[]={"caps","appEndpoints","s",NULL};
    for(unsigned i=0;arrays[i];i++){int array=wn_doc_member(&d,(unsigned)body,arrays[i]);if(array>=0 && (d.tokens[array].type!='[' || (uint8_t)d.text[d.tokens[array].start]!=0x80))return -1;}
    static const char *const texts[]={"agentTransport","platform",NULL};
    for(unsigned i=0;texts[i];i++){int text=wn_doc_member(&d,(unsigned)body,texts[i]);if(text>=0 && !wn_doc_equal(&d,text,""))return -1;}
    int route=wn_doc_member(&d,(unsigned)body,"route");
    uint64_t seqno;char prefix[64];uint8_t expected[16];
    if(route<0 || d.tokens[route].type!='{' ||
       number(&d,(unsigned)route,"routerId",&p.origin.router_id) || !p.origin.router_id || p.origin.router_id==UINT64_MAX ||
       number(&d,(unsigned)route,"seqno",&seqno) || seqno>UINT16_MAX ||
       wn_doc_string(&d,wn_doc_member(&d,(unsigned)route,"prefix"),prefix,sizeof prefix)<=0 ||
       wno_address(p.principal,p.principal_size,p.instance,expected))return -1;
    size_t n=strlen(prefix);if(n<=4 || strcmp(prefix+n-4,"/128"))return -1;prefix[n-4]=0;
    if(inet_pton(AF_INET6,prefix,p.address)!=1 || memcmp(p.address,expected,16))return -1;
    p.origin.seqno=(uint16_t)seqno;*out=p;return 0;
}

int wno_init(struct wno_directory *d,const char *tenant,unsigned limit)
{
    uint8_t uuid[16];if(!d || wn_uuid_parse(tenant,uuid) || !limit || limit>WNO_DIRECTORY_MAX)return -1;
    *d=(struct wno_directory){.limit=limit};memcpy(d->tenant,tenant,37);return 0;
}
void wno_deinit(struct wno_directory *d)
{
    if(!d)return;
    while(d->entries){struct wno_entry *e=d->entries;d->entries=e->next;wendy_net_free(e);}memset(d,0,sizeof *d);
}
void wno_expire(struct wno_directory *d,int64_t now)
{
    if(!d || now<0)return;
    struct wno_entry **at=&d->entries;
    while(*at){struct wno_entry *e=*at;if(e->retain_until_us<=now){*at=e->next;wendy_net_free(e);d->count--;}else at=&e->next;}
}
int wno_accept_manifest_verified(struct wno_directory *d,const struct wno_manifest *p,
    const struct wendy_pki_operator_peer *identity,int64_t now,int64_t monotonic)
{
    if(!d || !d->limit || !p || !identity || now<=0 || now>INT64_MAX-905000 || monotonic<0 || monotonic>INT64_MAX-INT64_C(905000000) ||
       wendy_pki_operator_principal(p->principal,p->principal_size,d->tenant) ||
       strnlen(identity->principal,sizeof identity->principal)!=p->principal_size || memcmp(identity->principal,p->principal,p->principal_size) ||
       identity->expires<=0 || identity->expires>INT64_MAX/1000 || p->expires>(int64_t)identity->expires*1000 ||
       p->issued>now+5000 || p->expires<=p->issued || p->expires-p->issued>900000 || !p->revision)return -1;
    if(!p->hash_count || memcmp(p->hashes[0],identity->leaf_hash,32))return -1;
    if(p->expires<=now)return 1;
    uint8_t digest[32];if(wendy_pki_sha256(p->body,p->body_size,digest))return -1;
    wno_expire(d,monotonic);
    struct wno_entry *e=d->entries;
    while(e && !(e->principal_size==p->principal_size && !memcmp(e->principal,p->principal,p->principal_size) && !memcmp(e->instance,p->instance,16)))e=e->next;
    if(e && p->revision<e->revision)return 1;
    if(e && p->revision==e->revision && memcmp(e->digest,digest,32))return -1;
    if(!e){
        if(d->count>=d->limit)return 3;
        e=wendy_net_calloc(1,sizeof *e+p->principal_size+1);if(!e)return 3;
        memcpy(e->principal,p->principal,p->principal_size);e->principal_size=p->principal_size;
        memcpy(e->instance,p->instance,16);e->next=d->entries;d->entries=e;d->count++;
    }
    int64_t deadline=p->withdraw ? 0:monotonic+(p->expires-now)*1000;
    if(e->revision==p->revision && deadline>e->deadline_us)deadline=e->deadline_us;
    e->deadline_us=deadline;e->retain_until_us=monotonic+INT64_C(905000000);e->revision=p->revision;
    e->origin=p->origin;memcpy(e->address,p->address,16);memcpy(e->digest,digest,32);return 0;
}
static const struct wno_entry *owner(const struct wno_directory *d,const uint8_t address[16],int64_t now)
{
    if(!d || !address || now<0)return NULL;
    const struct wno_entry *found=NULL;
    for(const struct wno_entry *e=d->entries;e;e=e->next)if(e->deadline_us>now && !memcmp(e->address,address,16)){if(found)return NULL;found=e;}
    return found;
}
bool wno_live_address(const struct wno_directory *d,const uint8_t address[16],int64_t now)
{return owner(d,address,now)!=NULL;}
bool wno_authorizes(const struct wno_directory *d,const uint8_t address[16],uint64_t router,uint16_t seqno,int64_t now)
{const struct wno_entry *e=owner(d,address,now);return e && e->origin.router_id==router && e->origin.seqno==seqno;}
size_t wno_memory(const struct wno_directory *d)
{size_t bytes=0;if(d)for(const struct wno_entry *e=d->entries;e;e=e->next)bytes+=sizeof *e+e->principal_size+1;return bytes;}
