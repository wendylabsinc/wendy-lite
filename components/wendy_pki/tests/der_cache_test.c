/* Public own-certificate cache lifecycle, using ordinary enrolled fixture DER. */
#include "wendy_pki_der_cache.h"
#include "wendy_pki_crypto.h"
#include "wendy_pki_public_index.h"
#include "wendy_cert_bundle.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct blob {char key[16];uint8_t *data;size_t size;};
static struct blob blobs[1040];
static unsigned writes,commits;
static struct blob *find(const char *key,bool create)
{
    struct blob *empty=NULL;
    for(size_t i=0;i<sizeof blobs/sizeof *blobs;i++){
        if(!strcmp(blobs[i].key,key))return &blobs[i];
        if(!blobs[i].key[0])empty=&blobs[i];
    }
    if(!create)return NULL;
    assert(empty && strlen(key)<sizeof empty->key);strcpy(empty->key,key);return empty;
}
esp_err_t nvs_get_blob(nvs_handle_t h,const char *key,void *out,size_t *size)
{
    assert(h==1);struct blob *blob=find(key,false);
    if(!blob)return ESP_ERR_NVS_NOT_FOUND;
    if(out){if(*size<blob->size)return ESP_ERR_INVALID_SIZE;memcpy(out,blob->data,blob->size);}
    *size=blob->size;return ESP_OK;
}
esp_err_t nvs_set_blob(nvs_handle_t h,const char *key,const void *data,size_t size)
{
    assert(h==1);struct blob *blob=find(key,true);uint8_t *copy=malloc(size);assert(copy);
    memcpy(copy,data,size);free(blob->data);blob->data=copy;blob->size=size;writes++;return ESP_OK;
}
esp_err_t nvs_erase_key(nvs_handle_t h,const char *key)
{
    assert(h==1);struct blob *blob=find(key,false);if(!blob)return ESP_ERR_NVS_NOT_FOUND;
    free(blob->data);*blob=(struct blob){0};writes++;return ESP_OK;
}
esp_err_t nvs_commit(nvs_handle_t h){assert(h==1);commits++;return ESP_OK;}
bool wendy_conf_snapshot_current(uint64_t generation){(void)generation;return true;}
bool wendy_pki_reset_in_progress(void){return false;}
int main(int argc,char **argv)
{
    assert(argc==2 && !wendy_pki_crypto_init());
    FILE *file=fopen(argv[1],"rb");assert(file && !fseek(file,0,SEEK_END));
    long length=ftell(file);assert(length>0 && !fseek(file,0,SEEK_SET));
    uint8_t *pem=malloc((size_t)length);assert(pem && fread(pem,1,(size_t)length,file)==(size_t)length);fclose(file);
    size_t size=0;assert(!wendy_cert_bundle_measure(pem,(size_t)length,&size));
    uint8_t *der=malloc(size);assert(der && !wendy_cert_bundle_import(pem,(size_t)length,der,size,&size));free(pem);
    assert(nvs_set_blob(1,"certificate",der,size)==ESP_OK);
    struct pki_der_source source;assert(pki_der_cache_open(1,&source));
    assert(!pki_der_cache_build(1,der,size));assert(!pki_der_cache_open(1,&source));
    assert(source.count==1 && !source.ranges);
    uint8_t *copy=NULL;size_t loaded=0;
    assert(pki_der_cache_read(&source,0,&copy,&loaded)==1 && loaded==size && !memcmp(copy,der,size));free(copy);
    assert(pki_der_cache_read(&source,1,&copy,&loaded)==0 && !copy && !loaded);
    assert(!pki_der_cache_prepare_ranges(&source) && source.ranges);
    unsigned before_writes=writes,before_commits=commits;
    for(unsigned repeat=0;repeat<3;repeat++){
        assert(!pki_der_cache_open(1,&source) && !pki_der_cache_prepare_ranges(&source));
        uint8_t hash[32];assert(pki_der_cache_hash(&source,0,hash,&loaded)==1 && loaded==size);
        size_t offset=0;
        while(offset<size){uint8_t out[1024];size_t total=0;
            int n=pki_der_cache_part(&source,hash,offset,out,&total);
            assert(n>0 && total==size && !memcmp(out,der+offset,(size_t)n));offset+=(size_t)n;
        }
        size_t total=0;assert(pki_der_cache_part(&source,hash,0,NULL,&total)==1 && total==size);
    }
    assert(writes==before_writes && commits==before_commits); /* No per-session flash writes. */
    uint32_t epoch=pki_public_certificate_epoch();
    assert(!pki_der_cache_invalidate(1) && pki_public_certificate_epoch()!=epoch);
    assert(pki_der_cache_open(1,&source));
    /* A renewed certificate rebuilds the derived source once, then reads only. */
    assert(nvs_set_blob(1,"certificate",der,size)==ESP_OK && !pki_der_cache_build(1,der,size));
    assert(!pki_der_cache_open(1,&source) && !pki_der_cache_prepare_ranges(&source));
    before_writes=writes;before_commits=commits;
    assert(!pki_der_cache_open(1,&source) && !pki_der_cache_prepare_ranges(&source));
    assert(writes==before_writes && commits==before_commits);
    for(size_t i=0;i<sizeof blobs/sizeof *blobs;i++)free(blobs[i].data);
    free(der);puts("own DER cache: full/range readers agree; repeated sessions write no flash; renewal invalidates first");return 0;
}
