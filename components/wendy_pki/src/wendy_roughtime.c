/* Compatible with WendyOS's pinned draft-08/11 Roughtime implementation. */
#include "wendy_roughtime.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/hash.h>

typedef struct { const uint8_t *p; size_t n; } span;
static uint32_t u32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1]<<8 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24; }
static uint64_t u64(const uint8_t *p) { return (uint64_t)u32(p) | (uint64_t)u32(p+4)<<32; }
static void put32(uint8_t *p, uint32_t v) { for (int i=0;i<4;i++) p[i]=(uint8_t)(v>>(8*i)); }
#define CHECK(x) do { if (!(x)) return -1; } while (0)

/* Validate the entire table, including tags not consumed by the caller. */
static int field(span m, const char tag[4], span *out)
{
    CHECK(m.n >= 4);
    uint32_t n=u32(m.p), wanted=u32((const uint8_t *)tag), previous=0;
    CHECK(n && n<=m.n/8);
    size_t header=(size_t)n*8, start=0;
    *out=(span){0};
    for (uint32_t i=0;i<n;i++) {
        uint32_t t=u32(m.p+4*n+4*i);
        size_t end=i+1<n ? u32(m.p+4+4*i) : m.n-header;
        CHECK((i==0 || t>previous) && end>=start && end<=m.n-header && end%4==0);
        if (t==wanted) *out=(span){m.p+header+start,end-start};
        start=end; previous=t;
    }
    return out->p ? 0 : -1;
}
static int signature(span sig, span body, const uint8_t key[32], const char *context, size_t context_size)
{
    CHECK(sig.n==64 && body.n<=WENDY_RT_MAX_RESPONSE);
    uint8_t *message=malloc(context_size+body.n);
    CHECK(message);
    memcpy(message,context,context_size); memcpy(message+context_size,body.p,body.n);
    ed25519_key k; int valid=0, r=wc_ed25519_init(&k);
    if (!r) {
        r=wc_ed25519_import_public(key,32,&k);
        if (!r) r=wc_ed25519_verify_msg(sig.p,64,message,(word32)(context_size+body.n),&valid,&k);
        wc_ed25519_free(&k);
    }
    free(message);
    return r || !valid ? -1 : 0;
}
int wendy_rt_verify(const uint8_t *response, size_t size, const uint8_t nonce[32],
                    const uint8_t root_key[32], struct wendy_rt_interval *out)
{
    CHECK(response && nonce && root_key && out && size<=WENDY_RT_MAX_RESPONSE && size>=12);
    CHECK(!memcmp(response,"ROUGHTIM",8) && u32(response+8)==size-12);
    span m={response+12,size-12}, ver, cert, csig, dele, key, mint, maxt, sig, rep, mid, rad, root, index, path, echoed;
    CHECK(!field(m,"VER\0",&ver) && ver.n==4 && (u32(ver.p)==0x80000008 || u32(ver.p)==0x8000000b));
    /* NONC is optional in these drafts; the signed Merkle proof is mandatory. */
    if (!field(m,"NONC",&echoed)) CHECK(echoed.n==32 && !memcmp(echoed.p,nonce,32));
    CHECK(!field(m,"CERT",&cert) && !field(cert,"SIG\0",&csig) && !field(cert,"DELE",&dele));
    static const char cc[]="RoughTime v1 delegation signature--";
    CHECK(!signature(csig,dele,root_key,cc,sizeof cc));
    CHECK(!field(dele,"PUBK",&key) && key.n==32 && !field(dele,"MINT",&mint) && mint.n==8 && !field(dele,"MAXT",&maxt) && maxt.n==8);
    CHECK(!field(m,"SIG\0",&sig) && !field(m,"SREP",&rep));
    static const char sc[]="RoughTime v1 response signature";
    CHECK(!signature(sig,rep,key.p,sc,sizeof sc));
    CHECK(!field(rep,"MIDP",&mid) && mid.n==8 && !field(rep,"RADI",&rad) && rad.n==4 && !field(rep,"ROOT",&root) && root.n==32);
    uint64_t midpoint=u64(mid.p), minimum=u64(mint.p), maximum=u64(maxt.p);
    uint32_t radius=u32(rad.p);
    CHECK(minimum<=maximum && midpoint>=minimum && midpoint<=maximum && radius<=10);
    CHECK(midpoint>=radius && midpoint<=(uint64_t)INT64_MAX/1000000-radius);
    CHECK(!field(m,"INDX",&index) && index.n==4 && !field(m,"PATH",&path) && path.n%32==0 && path.n<=32*32);
    uint32_t idx=u32(index.p);
    uint8_t input[65], hash[64]; input[0]=0; memcpy(input+1,nonce,32);
    CHECK(!wc_Sha512Hash(input,33,hash));
    for (size_t i=0;i<path.n;i+=32) {
        input[0]=1;
        memcpy(input+1+(idx&1 ? 32:0),hash,32);
        memcpy(input+1+(idx&1 ? 0:32),path.p+i,32);
        CHECK(!wc_Sha512Hash(input,65,hash)); idx>>=1;
    }
    CHECK(!idx && !memcmp(hash,root.p,32));
    out->lower=(int64_t)(midpoint-radius)*1000000;
    out->upper=(int64_t)(midpoint+radius)*1000000;
    return 0;
}
void wendy_rt_request(uint8_t request[1024], const uint8_t nonce[32], const uint8_t key[32])
{
    memset(request,0,1024); memcpy(request,"ROUGHTIM",8); put32(request+8,1012);
    uint8_t *m=request+12; put32(m,4);
    put32(m+4,8); put32(m+8,40); put32(m+12,72);
    memcpy(m+16,"VER\0SRV\0NONCZZZZ",16);
    put32(m+32,0x8000000b); put32(m+36,0x80000008);
    uint8_t input[33], hash[64]; input[0]=255; memcpy(input+1,key,32);
    wc_Sha512Hash(input,33,hash); memcpy(m+40,hash,32); memcpy(m+72,nonce,32);
}
int wendy_rt_consensus(const struct wendy_rt_interval v[WENDY_RT_SERVERS], unsigned mask,
                      struct wendy_rt_interval *out)
{
    int best=0; struct wendy_rt_interval chosen={0}; int ambiguous=0;
    for (unsigned subset=1;subset<(1u<<WENDY_RT_SERVERS);subset++) {
        if ((subset&mask)!=subset) continue;
        int count=0; struct wendy_rt_interval x={INT64_MIN,INT64_MAX};
        for (int i=0;i<WENDY_RT_SERVERS;i++) if (subset&(1u<<i)) {
            count++; if (v[i].lower>x.lower) x.lower=v[i].lower;
            if (v[i].upper<x.upper) x.upper=v[i].upper;
        }
        if (x.lower>x.upper || count<2 || count<best) continue;
        if (count>best) { best=count; chosen=x; ambiguous=0; }
        else if (x.upper<chosen.lower || x.lower>chosen.upper) ambiguous=1;
    }
    CHECK(best>=2 && !ambiguous); *out=chosen; return 0;
}
