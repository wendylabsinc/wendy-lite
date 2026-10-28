#include "wendy_pki_der_cache.h"
#include "wendy_pki_alloc.h"
#include "wendy_pki_crypto.h"
#include "wendy_pki_parsed_identity.h"
#include "wendy_cert_bundle.h"
#include "wendy_pki_public_index.h"
#include <mbedtls/x509.h>
#include <psa/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#if ESP_PLATFORM
#include "esp_log.h"
#include "esp_timer.h"
#endif

#define META_KEY "net_der_meta"
#define META_HEADER 41
#define META_SIZE (META_HEADER + 32 * PKI_DER_PARTS)
#define RANGE_KEY "net_der_ranges"
#define RANGE_CHUNK 512U
#define RANGE_META_SIZE (5 + 36 * PKI_DER_PARTS)
/* Preparation runs under the existing identity lock. Avoid repeated flash
 * writes after an optional cache misses its storage/RAM budget this boot. */
static bool ranges_attempted;
static uint8_t ranges_attempt_hash[32];
static atomic_bool range_reader_reported;
static void range_key(unsigned part,unsigned chunk,char key[16])
{
    memcpy(key,"nd_0_000",sizeof("nd_0_000"));
    key[3]=(char)('0'+part);
    key[5]=(char)('0'+chunk/100);
    key[6]=(char)('0'+chunk/10%10);
    key[7]=(char)('0'+chunk%10);
}
static void part_key(unsigned index, char key[16])
{
    memcpy(key,"net_der_0",sizeof("net_der_0"));
    key[8]=(char)('0'+index); /* All callers bound index to0..7. */
}
static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 |
           p[3];
}
static void put32(uint8_t *p, uint32_t n)
{
    for (unsigned i = 0; i < 4; i++)
        p[3 - i] = (uint8_t)(n >> (8 * i));
}
int pki_der_cache_invalidate(nvs_handle_t h)
{
    pki_public_certificate_changed();
    ranges_attempted=false;
    range_reader_reported=false;
    esp_err_t r = nvs_erase_key(h, META_KEY);
    esp_err_t ranges=nvs_erase_key(h,RANGE_KEY);
    if((r!=ESP_OK && r!=ESP_ERR_NVS_NOT_FOUND) ||
       (ranges!=ESP_OK && ranges!=ESP_ERR_NVS_NOT_FOUND))return -1;
    return (r==ESP_ERR_NVS_NOT_FOUND && ranges==ESP_ERR_NVS_NOT_FOUND) ||
           nvs_commit(h)==ESP_OK ? 0:-1;
}
int pki_der_cache_open(nvs_handle_t h, struct pki_der_source *source)
{
    uint8_t meta[META_SIZE];
    size_t size = sizeof meta, certificate_size = 0;
    memset(source, 0, sizeof *source);
    if (nvs_get_blob(h, META_KEY, meta, &size) != ESP_OK ||
        size < META_HEADER || memcmp(meta, "WDC1", 4) || !meta[4] ||
        meta[4] > PKI_DER_PARTS || size != META_HEADER + 32U * meta[4] ||
        nvs_get_blob(h, "certificate", NULL, &certificate_size) != ESP_OK ||
        certificate_size != get32(meta + 5))
        return -1;
    source->handle = h;
    source->count = meta[4];
    memcpy(source->hashes, meta + META_HEADER, 32U * source->count);
    uint8_t ranges[RANGE_META_SIZE];size_t range_size=sizeof ranges;
    if(nvs_get_blob(h,RANGE_KEY,ranges,&range_size)==ESP_OK &&
       range_size==5U+36U*source->count && !memcmp(ranges,"WDR1",4) &&
       ranges[4]==source->count){
        source->ranges=true;
        for(unsigned i=0;i<source->count;i++){
            const uint8_t *part=ranges+5+36*i;
            source->sizes[i]=get32(part);
            if(!source->sizes[i] || source->sizes[i]>65536 ||
               memcmp(part+4,source->hashes[i],32))source->ranges=false;
        }
    }
    return 0;
}

int pki_der_cache_prepare_ranges(struct pki_der_source *source)
{
    if(source->ranges)return 0;
    if(!source->count || source->count>PKI_DER_PARTS)return -1;
    uint8_t hash[32];
    if(wendy_pki_sha256((const uint8_t *)source->hashes,32U*source->count,hash))return -1;
    if(ranges_attempted && !memcmp(hash,ranges_attempt_hash,32))return -1;
    memcpy(ranges_attempt_hash,hash,32);ranges_attempted=true;
    pki_public_certificate_changed();
#if ESP_PLATFORM
    int64_t started=esp_timer_get_time();
    nvs_stats_t before={0};
    bool measured=nvs_get_stats("wendy_pki",&before)==ESP_OK;
#endif
    esp_err_t erased=nvs_erase_key(source->handle,RANGE_KEY);
    if((erased!=ESP_OK && erased!=ESP_ERR_NVS_NOT_FOUND) ||
       (erased==ESP_OK && nvs_commit(source->handle)!=ESP_OK))return -1;
    /* Bound persistent storage across ordinary certificate renewals. Range
     * metadata is already invalid, so unused chunks from an older/larger
     * chain may be removed without touching the full-part fallback. */
    bool changed=false;
    for(unsigned part=0;part<PKI_DER_PARTS;part++)
        for(unsigned chunk=0;chunk<65536/RANGE_CHUNK;chunk++){
            char key[16];range_key(part,chunk,key);
            esp_err_t r=nvs_erase_key(source->handle,key);
            if(r==ESP_OK)changed=true;
            else if(r!=ESP_ERR_NVS_NOT_FOUND)return -1;
        }
    if(changed && nvs_commit(source->handle)!=ESP_OK)return -1;
    uint8_t meta[RANGE_META_SIZE]={0};memcpy(meta,"WDR1",4);meta[4]=source->count;
    size_t bytes=0;unsigned chunks=0;
    for(unsigned i=0;i<source->count;i++){
        uint8_t *der=NULL;size_t size=0;
        if(pki_der_cache_read(source,i,&der,&size)!=1)return -1;
        put32(meta+5+36*i,(uint32_t)size);
        bytes+=size;
        memcpy(meta+9+36*i,source->hashes[i],32);
        for(size_t offset=0;offset<size;offset+=RANGE_CHUNK){
            size_t n=size-offset;if(n>RANGE_CHUNK)n=RANGE_CHUNK;
            char key[16];range_key(i,(unsigned)(offset/RANGE_CHUNK),key);
            if(nvs_set_blob(source->handle,key,der+offset,n)!=ESP_OK){pki_owned_free(der);return -1;}
            chunks++;
        }
        pki_owned_free(der);
    }
    if(nvs_set_blob(source->handle,RANGE_KEY,meta,5+36U*source->count)!=ESP_OK ||
       nvs_commit(source->handle)!=ESP_OK)return -1;
    if(pki_der_cache_open(source->handle,source) || !source->ranges)return -1;
#if ESP_PLATFORM
    nvs_stats_t after={0};
    measured=measured && nvs_get_stats("wendy_pki",&after)==ESP_OK;
    ESP_LOGI("wendy_pki","public DER ranges cached: parts=%u bytes=%u chunks=%u NVS_entry_delta=%d free_entries=%u ms=%u",
        source->count,(unsigned)bytes,chunks,
        measured ? (int)after.used_entries-(int)before.used_entries:-1,
        measured ? (unsigned)after.free_entries:0,
        (unsigned)((esp_timer_get_time()-started)/1000));
#else
    (void)bytes;(void)chunks;
#endif
    return 0;
}

int pki_der_cache_read_range(void *context,unsigned index,size_t offset,
                             uint8_t *output,size_t count,const uint8_t expected[32])
{
    struct pki_der_source *source=context;
    if(index>=source->count || index>=PKI_DER_PARTS || !expected ||
       (!output && count) || memcmp(expected,source->hashes[index],32))return -1;
    if(!source->ranges){
        uint8_t *der=NULL;size_t size=0;
        if(pki_der_cache_read(source,index,&der,&size)!=1)return -1;
        bool valid=offset<=size && count<=size-offset;
        if(valid && count)memcpy(output,der+offset,count);
        pki_owned_free(der);return valid ? (int)count:-1;
    }
    size_t size=source->sizes[index];
    if(!size || size>65536 || offset>size || count>size-offset)return -1;
    uint8_t *chunk=pki_owned_malloc(RANGE_CHUNK),digest[32];
    if(!chunk)return -1;
    psa_hash_operation_t operation=PSA_HASH_OPERATION_INIT;
    int result=-1;
    if(wendy_pki_crypto_init() || psa_hash_setup(&operation,PSA_ALG_SHA_256)!=PSA_SUCCESS)goto done;
    for(size_t at=0;at<size;at+=RANGE_CHUNK){
        size_t wanted=size-at;if(wanted>RANGE_CHUNK)wanted=RANGE_CHUNK;
        size_t loaded=RANGE_CHUNK;char key[16];range_key(index,(unsigned)(at/RANGE_CHUNK),key);
        if(nvs_get_blob(source->handle,key,chunk,&loaded)!=ESP_OK || loaded!=wanted ||
           psa_hash_update(&operation,chunk,loaded)!=PSA_SUCCESS)goto done;
        size_t first=at>offset ? at:offset;
        size_t last=at+loaded<offset+count ? at+loaded:offset+count;
        if(last>first)memcpy(output+first-offset,chunk+first-at,last-first);
    }
    size_t written=0;
    if(psa_hash_finish(&operation,digest,sizeof digest,&written)==PSA_SUCCESS &&
       written==32 && !memcmp(digest,expected,32))result=(int)count;
#if ESP_PLATFORM
    if(result>=0 && !atomic_exchange(&range_reader_reported,true)){
        ESP_LOGI("wendy_pki","verified public DER range reader active: scratch=%u",RANGE_CHUNK);
    }
#endif
done:
    psa_hash_abort(&operation);pki_owned_free(chunk);return result;
}
int pki_der_cache_hash(void *context,unsigned index,uint8_t digest[32],size_t *size)
{
    struct pki_der_source *source=context;
    *size=0;
    if(index>=source->count)return index==source->count ? 0:-1;
    if(source->ranges){
        /* A zero-length range still hashes every stored chunk and compares
         * the result with this source's exact full-part digest. */
        if(pki_der_cache_read_range(source,index,0,NULL,0,source->hashes[index]))return -1;
        memcpy(digest,source->hashes[index],32);*size=source->sizes[index];return 1;
    }
    uint8_t *der=NULL;
    int result=pki_der_cache_read(source,index,&der,size);
    if(result==1 && wendy_pki_sha256(der,*size,digest))result=-1;
    pki_owned_free(der);return result;
}
int pki_der_cache_read(void *context, unsigned index, uint8_t **bytes,
                       size_t *size)
{
    struct pki_der_source *s = context;
    *bytes = NULL;
    *size = 0;
    if (index >= s->count)
        return index == s->count ? 0 : -1;
    char key[16];
    part_key(index, key);
    if (nvs_get_blob(s->handle, key, NULL, size) != ESP_OK || !*size ||
        *size > 65536)
    {
        return -1;
    }
    uint8_t *der = pki_owned_malloc(*size);
    if (!der)
        return MBEDTLS_ERR_X509_ALLOC_FAILED;
    uint8_t digest[32];
    if (nvs_get_blob(s->handle, key, der, size) != ESP_OK ||
        wendy_pki_sha256(der, *size, digest) ||
        memcmp(digest, s->hashes[index], 32))
    {
        pki_owned_free(der);
        return -1;
    }
    *bytes = der;
    return 1;
}
int pki_der_cache_build(nvs_handle_t h,const uint8_t *der,size_t size)
{
    size_t measured=0,source_size=0;
    if(!der || !size || der[0]!=0x30 || wendy_cert_bundle_measure(der,size,&measured) ||
       measured!=size || pki_der_cache_invalidate(h) ||
       nvs_get_blob(h,"certificate",NULL,&source_size)!=ESP_OK)return -1;
    uint8_t meta[META_SIZE]={0};memcpy(meta,"WDC1",4);
    put32(meta+5,(uint32_t)source_size);
    if(wendy_pki_sha256(der,size,meta+9))return -1;
    size_t offset=0,bytes;const uint8_t *part;unsigned count=0;int next;
    while((next=wendy_cert_der_next(der,size,&offset,&part,&bytes))==1){
        if(count==PKI_DER_PARTS)return -1;
        char key[16];part_key(count,key);
        if(wendy_pki_sha256(part,bytes,meta+META_HEADER+32*count) ||
           nvs_set_blob(h,key,part,bytes)!=ESP_OK)return -1;
        count++;
    }
    if(next || !count)return -1;
    meta[4]=(uint8_t)count;
    return nvs_set_blob(h,META_KEY,meta,META_HEADER+32*count)==ESP_OK &&
           nvs_commit(h)==ESP_OK ? 0:-1;
}

int pki_der_cache_part(struct pki_der_source *source,const uint8_t hash[32],size_t offset,
                       uint8_t out[1024],size_t *total)
{
    if(!source || !hash || !total)return -1;
    *total=0;
    unsigned index=0;while(index<source->count && memcmp(source->hashes[index],hash,32))index++;
    if(index==source->count)return -1;
    if(source->ranges){
        size_t size=source->sizes[index];
        if(!size || offset>=size)return -1;
        size_t n=size-offset;if(n>1024)n=1024;
        int result=pki_der_cache_read_range(source,index,offset,out,out ? n:0,hash);
        if(result<0)return -1;
        *total=size;return out ? (int)n:1;
    }
    /* A once-per-certificate range cache may be unavailable. Read the existing
     * whole part without invoking the legacy reader's invalidation/repair path. */
    char key[16];part_key(index,key);size_t size=0;
    if(nvs_get_blob(source->handle,key,NULL,&size)!=ESP_OK || !size || size>65536 || offset>=size)return -1;
    uint8_t *der=pki_owned_malloc(size),digest[32];if(!der)return -1;
    size_t loaded=size;int result=-1;
    if(nvs_get_blob(source->handle,key,der,&loaded)==ESP_OK && loaded==size &&
       !wendy_pki_sha256(der,size,digest) && !memcmp(digest,hash,32)){
        size_t n=size-offset;if(n>1024)n=1024;
        if(out)memcpy(out,der+offset,n);
        *total=size;result=out ? (int)n:1;
    }
    pki_owned_free(der);return result;
}
