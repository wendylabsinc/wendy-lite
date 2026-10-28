/* Ordinary public-chain transfer, shared issuer reuse and output backpressure.
 * Full certificate verification belongs to the existing PKI adapter. */
#include "../src/certificate_fetch.h"
#include "../src/certificate_wire.h"
#include "wendy_pki_crypto.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct part {uint8_t hash[32];uint8_t *bytes;size_t size;};
struct cache {struct part parts[3];unsigned count;bool busy;};
static int read_part(void *ctx,const uint8_t hash[32],size_t offset,
                     uint8_t out[WNCF_CHUNK],size_t *total)
{
    struct cache *cache=ctx;
    for(unsigned i=0;i<cache->count;i++){
        struct part *part=&cache->parts[i];
        if(memcmp(hash,part->hash,32))continue;
        assert(offset<part->size);*total=part->size;
        if(out){size_t n=part->size-offset;if(n>WNCF_CHUNK)n=WNCF_CHUNK;
            memcpy(out,part->bytes+offset,n);}
        return 1;
    }
    return 0;
}
static int store_part(void *ctx,const uint8_t hash[32],const void *bytes,size_t size)
{
    struct cache *cache=ctx;
    if(cache->busy)return 1;
    assert(cache->count<3);struct part *part=&cache->parts[cache->count++];
    memcpy(part->hash,hash,32);part->bytes=malloc(size);assert(part->bytes);
    memcpy(part->bytes,bytes,size);part->size=size;return 0;
}
int main(void)
{
    struct cache cache={0};struct wncf_store storage={.context=&cache,.read=read_part,.put=store_part};
    struct wncf_fetch fetch={0};struct wncf_chain chain={.count=3};
    strcpy(chain.principal,"spiffe://wendy.sh/tenant/2558fd76-afc7-466e-9613-6b715296a526/device/00000000-0000-4000-8000-000000000004");
    uint8_t parts[3][3000];size_t sizes[]={512,2793,1100};
    for(unsigned i=0;i<3;i++){
        for(size_t j=0;j<sizes[i];j++)parts[i][j]=(uint8_t)(i*31+j*13);
        assert(!wendy_pki_sha256(parts[i],sizes[i],chain.hashes[i]));
    }
    char wire[2048];struct wn_doc document;struct wncf_chain decoded;
    int length=wncf_chain_write(&chain,wire,sizeof wire);assert(length>0);
    assert(!wn_doc_parse(&document,wire,(size_t)length));
    int envelope=wn_doc_member(&document,0,"certificate");assert(envelope>=0);
    int value=wn_doc_member(&document,(unsigned)envelope,"chain");assert(value>=0);
    assert(!wncf_chain_read(&document,(unsigned)value,"2558fd76-afc7-466e-9613-6b715296a526",&decoded));
    assert(!strcmp(decoded.principal,chain.principal) && decoded.count==chain.count &&
        !memcmp(decoded.hashes,chain.hashes,chain.count*32));
    /* A shared issuer is already in storage; fetching needs no second copy. */
    assert(!store_part(&cache,chain.hashes[0],parts[0],sizes[0]));
    assert(!wncf_memory(&fetch) && !wncf_start(&fetch,&chain,1000));
    int64_t now=1001;unsigned requests=0;size_t peak=0;
    for(;;){
        struct wncf_request request,again;
        int r=wncf_next(&fetch,&storage,now++,&request);assert(r==1 || r==2);
        if(r==2)break;
        /* Queue admission can pause without consuming a request or offset. */
        assert(wncf_next(&fetch,&storage,now++,&again)==1);
        assert(!memcmp(request.hash,again.hash,32) && request.offset==again.offset);
        unsigned index=fetch.index;assert(index>0 && index<3);
        size_t n=sizes[index]-request.offset;if(n>WNCF_CHUNK)n=WNCF_CHUNK;
        length=wncf_request_write(&request,wire,sizeof wire);assert(length>0);
        assert(!wn_doc_parse(&document,wire,(size_t)length));
        envelope=wn_doc_member(&document,0,"certificate");assert(envelope>=0);
        value=wn_doc_member(&document,(unsigned)envelope,"request");assert(value>=0);
        assert(!wncf_request_read(&document,(unsigned)value,&again));
        assert(again.offset==request.offset && !memcmp(again.hash,request.hash,32));
        wncf_sent(&fetch,now++);assert(!wncf_next(&fetch,&storage,now++,&again));
        bool busy=index==1 && request.offset+n==sizes[index];cache.busy=busy;
        struct wncf_chunk chunk={.offset=request.offset,.total=sizes[index],.size=n};
        memcpy(chunk.hash,request.hash,32);
        length=wncf_chunk_write(&chunk,parts[index]+request.offset,wire,sizeof wire);assert(length>0);
        assert(!wn_doc_parse(&document,wire,(size_t)length));
        envelope=wn_doc_member(&document,0,"certificate");assert(envelope>=0);
        value=wn_doc_member(&document,(unsigned)envelope,"chunk");assert(value>=0);
        struct wncf_chunk received;uint8_t payload[WNCF_CHUNK];
        assert(!wncf_chunk_read(&document,(unsigned)value,&received,payload));
        assert(received.offset==chunk.offset && received.total==chunk.total && received.size==chunk.size &&
            !memcmp(received.hash,chunk.hash,32) && !memcmp(payload,parts[index]+request.offset,n));
        r=wncf_receive(&fetch,&storage,request.hash,request.offset,sizes[index],
            payload,n,now++);assert(r==(busy ? 1:0));requests++;
        size_t used=wncf_memory(&fetch);if(used>peak)peak=used;
        if(busy){
            assert(!wncf_next(&fetch,&storage,now++,&again));
            cache.busy=false;
        }
    }
    assert(requests==5 && cache.count==3 && !fetch.bytes);
    assert(wncf_memory(&fetch)==sizeof(struct wncf_chain));
    for(unsigned i=0;i<3;i++){
        assert(cache.parts[i].size==sizes[i] && !memcmp(cache.parts[i].bytes,parts[i],sizes[i]));
        free(cache.parts[i].bytes);
    }
    wncf_stop(&fetch);assert(!wncf_memory(&fetch));
    /* Ordinary eviction after the first chunk: a miss releases the full
     * partially allocated DER buffer immediately, without an idle timeout. */
    struct cache cold={0};struct wncf_store empty={.context=&cold,.read=read_part,.put=store_part};
    assert(!wncf_start(&fetch,&chain,2000));
    struct wncf_request missing;
    assert(wncf_next(&fetch,&empty,2001,&missing)==1);wncf_sent(&fetch,2002);
    assert(!wncf_receive(&fetch,&empty,missing.hash,0,sizes[0],parts[0],sizes[0],2003));
    assert(wncf_next(&fetch,&empty,2004,&missing)==1);wncf_sent(&fetch,2005);
    assert(!wncf_receive(&fetch,&empty,missing.hash,0,sizes[1],parts[1],WNCF_CHUNK,2006));
    assert(wncf_next(&fetch,&empty,2007,&missing)==1 && missing.offset==WNCF_CHUNK);
    wncf_sent(&fetch,2008);assert(fetch.bytes && wncf_memory(&fetch)>sizes[1]);
    {
        length=wncf_missing_write(&missing,wire,sizeof wire);assert(length>0);
        assert(!wn_doc_parse(&document,wire,(size_t)length));
        envelope=wn_doc_member(&document,0,"certificate");assert(envelope>=0);
        value=wn_doc_member(&document,(unsigned)envelope,"missing");assert(value>=0);
        struct wncf_request decoded_missing;assert(!wncf_request_read(&document,(unsigned)value,&decoded_missing));
        assert(decoded_missing.offset==missing.offset && !memcmp(decoded_missing.hash,missing.hash,32));
    }
    assert(wncf_missing(&fetch,&missing) && !wncf_memory(&fetch));
    for(unsigned i=0;i<cold.count;i++)free(cold.parts[i].bytes);
    printf("Cold transfer, shared public part and busy retry pass; peak=%zu idle=0 bytes\n",peak);
    return 0;
}
